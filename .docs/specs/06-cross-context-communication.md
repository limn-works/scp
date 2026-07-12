# 6. Cross-Context Communication

## 6.1 Agent Isolation

Agents cannot cross contexts at the protocol level. This is absolute. An agent in Context A cannot send a message to Context B, read Context B's state, or interact with Context B's outlets or members. From the protocol's perspective, the agent in A and the agent in B (even if operated by the same human) are entirely separate instances.

Information may cross context boundaries through two protocol-level mechanisms:

1. **Cross-context outlet interfaces (§6.2)** — asymmetric, structured, request/response. One context queries another's outlet. Governed by both contexts per call.
2. **Multi-parent child contexts (§5.13)** — symmetric, full context. A shared space governed by multiple parent contexts. Members from different parents interact as peers.

Both mechanisms require explicit consent from all involved contexts. Neither allows agents to directly access another context's state. The first is for service-style interactions; the second is for collaborative ones.

## 6.2 Context-to-Context Outlet Interfaces

### 6.2.0 Outlet Interface Transport

Cross-context outlet calls require a physical transport mechanism to bridge the boundary between two isolated contexts. Two protocol-level mechanisms provide this:

1. **Shared-member bridging (primary).** When a human participates in both contexts, their SDK bridges outlet requests and responses locally. The human's agent in Context A makes an outlet call targeting Context B; the SDK routes the request through the human's membership in Context B, executes the call under Context B's governance, and returns the response to Context A. No relay-level cross-context routing is needed — the bridge operates entirely within the human's local SDK. Both contexts' governance is enforced: Context A's outbound policy and Context B's inbound policy are validated before the call proceeds. The human's SDK is the transport, and both event logs record the interaction with full provenance.

2. **Multi-parent child contexts (fallback).** For cases without a shared member, a child context with parents from both the source and target contexts can serve as a bridge (§5.13). The child context inherits capability ceilings from both parents (intersection). Members from both parent contexts who join the child context can mediate outlet calls within the child's governed space. This is heavier than shared-member bridging but covers the case where no single human has membership in both contexts.

These two mechanisms cover all cross-context outlet call scenarios. Direct agent-to-agent communication is not needed — outlet interfaces with stateful sessions (§6.2.1) provide the same functional coverage (negotiation, coordination, multi-step workflows) with stronger security guarantees: every interaction is context-governed, schema-declared, rate-limited, and auditable. The context governs the outlet call, not the agent.

Contexts can expose outlet endpoints to other contexts. **The context governs the outlet call, not the agent.** An agent in Context A does not directly contact Context B — the agent requests from Context A, Context A's governance decides whether to permit the outbound call, and Context B's governance decides whether to permit the inbound call and how to respond. Both contexts mediate. The agent never directly touches the other context.

This is the mechanism for all structured inter-agent interaction across context boundaries. Both contexts' governance models, capability ceilings, and role permissions gate every interaction.

Properties:

- Both contexts opt in explicitly (bidirectional consent at the context level, not the agent level — see §6.2.0.1 for the consent protocol).
- Data flows through defined function signatures, not through agent memory or discretion.
- Auditable: every call through an interface is logged in both contexts' event logs with full provenance (§7.7).
- Outlet interfaces carry provenance: data received through an interface carries its origin context, invoking agent, timestamp, and chain depth (§7.7.1).
- Rate-limited: both contexts can enforce rate limits on interface calls (see §6.2.0.2 for defaults).
- **Chain depth limit.** Cross-context outlet calls carry a `chain_depth` counter, incremented on each hop. An outlet call at maximum depth cannot trigger further cross-context outlet calls. Context-configurable via `ContextParams::max_chain_depth` (default: 8, range [1, 255]). There is no protocol hard maximum — chain depth is a context concern, and provenance quality naturally degrades with depth. This bounds amplification and makes transitive provenance degradation mechanically enforced (§9.2.1, §24.4, ADR-043).
- **Schema constraints.** Outlet schemas must satisfy a structural specificity floor at registration time — no unbounded string-only interfaces, minimum two distinct fields in input or output. This prevents degenerate broad-schema outlets that function as arbitrary message channels (§9.2.1).
- **Outlet-level costs.** Individual outlets may declare per-invocation costs in their registration metadata (§5.4). These are additive with context-level costs and carry their own payee DID. Cross-context outlet calls inherit the target outlet's cost structure. See §19.3 for economic policy and §19.2.2 for the payment integration sequence.

#### 6.2.0.1 Bidirectional Consent Protocol

Outlet interface creation requires explicit consent from both the exposing context and the consuming context. The consent protocol:

1. **Interface proposal.** An admin in Context A proposes exposing an outlet to Context B via a governance action:
   ```
   ProposeOutletInterface {
     outlet_id:      OutletId,     // Outlet to expose
     target_context: ContextId,    // Context B
     outbound_policy: OutboundPolicy,
     max_calls_per_minute: u32,    // Rate limit for this interface
   }
   ```
   This proposal follows Context A's governance model (§5.9).

2. **Outbound policy validation.** Context A validates that `outlet:interface` is in its ceiling (§5.3) and the proposer holds the `outlet:interface` capability.

3. **Interface offer.** On governance approval, Context A publishes an `InterfaceOffer` to its event log:
   ```
   InterfaceOffer {
     offer_id:       [u8; 32],     // SHA-256(context_a_id || outlet_id || context_b_id || timestamp)
     source_context: ContextId,    // Context A
     target_context: ContextId,    // Context B
     outlet_schema:  OutletRegistration, // Full outlet schema (§5.4.1)
     outbound_policy: OutboundPolicy,
     expires_at:     u64,          // Offer expires if not accepted within 7 days
   }
   ```

4. **Acceptance.** A shared member carries the offer to Context B (shared-member bridging). Context B's governance decides whether to accept:
   ```
   AcceptOutletInterface {
     offer_id:       [u8; 32],
     inbound_policy: InboundPolicy,
   }
   ```
   This follows Context B's governance model. Acceptance creates an `InterfaceEstablished` event in both event logs.

5. **Teardown.** Either context can revoke the interface at any time via governance action `RevokeOutletInterface { interface_id }`. Revocation is unilateral — no consent from the other side is needed. An `InterfaceRevoked` event is recorded in the revoking context's event log.

**Outbound and inbound policies:**

```
OutboundPolicy {
  allowed_callers:      Vec<DID>,   // DIDs in Context A authorized to use this interface.
                                    // Empty = any member with outlet:interface capability.
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

#### 6.2.0.2 Outlet Interface Rate Limit Defaults

Rate limits for cross-context outlet interfaces use a sliding window counter with the following defaults:

| Parameter | Default | Configurable range |
|-----------|---------|-------------------|
| Per-interface calls/minute | 60 | 1 - 6000 |
| Per-caller calls/minute | 10 | 1 - 1000 |
| Burst allowance | 5 (calls above limit within 1 second) | 0 - 50 |
| Window duration | 60 seconds (sliding) | 10 - 3600 seconds |

**Enforcement semantics.** When a rate limit is exceeded, the call is rejected with error code `OUTLET_INTERFACE_RATE_LIMITED` (code 4030). The response includes a `Retry-After` header indicating seconds until the next call will be accepted. Calls are NOT queued — rate-limited calls fail immediately. The caller's SDK MAY retry after the indicated delay.

**Per-caller vs. per-interface limits.** Both limits are enforced independently. A single caller is limited to 10 calls/minute by default; all callers combined are limited to 60 calls/minute per interface. This prevents a single caller from monopolizing an interface.

### 6.2.1 Stateful Outlet Sessions

Outlet interfaces support optional session-based multi-turn interaction. An outlet can accept a session identifier and maintain state across sequential invocations. This enables multi-step workflows (negotiation, coordination, iterative refinement) within the governed outlet call framework.

```
// First call: initiate a scheduling session
Context A → Context B outlet "schedule_meeting":
  input:  { action: "propose", times: ["Tue 3pm", "Thu 2pm"] }
  output: { session_id: "sched:abc123", status: "pending", counter: ["Tue 4pm"] }

// Second call: continue the session
Context A → Context B outlet "schedule_meeting":
  input:  { session_id: "sched:abc123", action: "accept", time: "Tue 4pm" }
  output: { session_id: "sched:abc123", status: "confirmed", time: "Tue 4pm" }
```

Session state is maintained by the outlet's context (Context B), not by the calling agent. Each call in the session is individually governed — Context A's governance permits each outbound call, Context B's governance permits each inbound call. The session does not create a persistent channel; it is a sequence of governed outlet calls that share state via an opaque session identifier.

Sessions have an optional TTL set by the outlet's context. When set, expired sessions are garbage-collected automatically. Sessions without a TTL persist for the lifetime of the context — appropriate for app-hosted sessions (games, workspaces, collaborative tools) where the context itself is the session's lifecycle boundary. Contexts enforce a per-caller session cap, context-configurable via `ContextParams::session_cap` (default: 1000 concurrent sessions per calling context), to prevent session exhaustion attacks regardless of TTL (§9.2.1, ADR-043). Session state is internal to the outlet's context and not visible to the calling context beyond the outlet's defined output schema.

### 6.2.2 Protocol-Level Discovery

Discovery is built from two complementary mechanisms: DID document capabilities (direct lookup) and contexts with discovery outlets (searchable registries). Together, these provide 0-setup discovery that makes SCP inherently social.

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

DID document capabilities provide direct lookup for any known DID. They do not provide search or browsing — for that, contexts with discovery outlets are needed.

#### B. Contexts with Discovery Outlets

These are standard SCP contexts with open join policies and standardized discovery outlets. Anyone can create one. No central authority, no operator dependency. They inherit all context-governed properties: outlet calls are rate-limited and auditable, results carry provenance.

**Standard discovery outlet schemas** — minimum interoperable interface:

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

These are conventions, not mandates — contexts with discovery outlets can add custom outlets (e.g., reputation scoring, category browsing, geographic filtering) beyond the standard schema. Contexts that support human-readable addressing (§22) additionally implement `handle_register`, `handle_lookup`, `handle_deregister`, and `attestation_lookup` outlets. Contexts that serve as scope registries (§22.3.5) additionally implement `scope_register`, `scope_lookup`, `scope_deregister` — independent outlets with separate storage, constrained to context-only targets and dot-free scope names (ADR-043).

**Two-tier membership model.** Contexts use a two-tier architecture to support unbounded scale while maintaining MLS-based governance:

- **Writer tier (MLS members, bounded).** Writers are standard MLS group members. They can register/deregister entries, modify governance, and process registration requests. The MLS group is bounded at ~500 members to maintain practical epoch advance costs (O(N) cost per MLS Update). Writers are typically registry operators, curators, and high-volume registrants.
- **Reader tier (DID-authenticated, unbounded).** Readers query the context's outlet endpoints via DID-signed requests without joining the MLS group. They can search (`agent_search`), inspect entries, and request inclusion proofs from the Merkle event log. No MLS membership required, no epoch advance cost. Reader capacity is unbounded.
- **Registration flow.** A reader (non-MLS-member) registers by sending a DID-signed registration request to the context's `agent_register` outlet endpoint. A writer processes the request and records it as an MLS application message in the event log. The registrant does NOT become an MLS member — their entry is stored in the context's registry data, and they can update or deregister via subsequent DID-authenticated requests to outlet endpoints, processed by writers.
- **Self-service updates.** Registered agents update their entries via DID-authenticated requests to outlet endpoints. Updates are subject to ownership enforcement:
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
- Apps can add domain-specific contexts with discovery outlets (e.g., a cooking community registry, a translation services directory).
- On first identity creation, the SDK auto-queries default contexts with discovery outlets and optionally self-registers (opt-out via configuration). Registration does not require MLS group membership.
- If all defaults are unavailable, agents fall back to direct DID resolution for known contacts and manual context ID sharing.

**Operation model.** Anyone can run a context with discovery outlets:

- Creator sets governance: who can register, metadata requirements, moderation rules (via standard context governance, enforced by writers).
- Storage: structured metadata entries (~100-500 bytes per agent), not conversation history. Scale is limited only by relay storage capacity — the MLS group (writers) stays small regardless of registry size.
- No operator dependency: if one registry disappears, agents use others. DID + capabilities persist in the agent's DID document regardless.

**SDK unification.** The SDK provides a unified discovery API:

- Searches local contact index (cache of previously resolved DID documents — instant)
- Queries each known context (standard outlet calls)
- Returns merged, deduplicated results ranked by relevance

**Privacy.** Registration is opt-in per context. Agents control what metadata they publish in each registry. Registration can be withdrawn at any time via `agent_deregister`. An agent can be registered in one context with full capabilities listed and in another with only a subset. DID document capabilities are controlled by the agent via DID document updates.

### 6.2.3 Broadcast Context Interactions

Outlet interfaces (§6.2) work with broadcast contexts. A broadcast context can expose outlets via the standard outlet interface mechanism — the context's governance mediates, the outlet schemas are declared, and calls are logged. Outlet invocation requires the invoker to hold the appropriate UCAN — a Query outlet requires `OutletQuery(outlet_id)` or `OutletQueryAll`, an Action outlet requires `OutletCall(outlet_id)` or `OutletCallAll` (§5.4.2) — which is governed by the broadcast context's role system.

**Mixed-mode nesting (§5.13).** Child contexts may have a different `ContextMode` than their parents. A Broadcast child of Encrypted parents enables public read access to curated content from a private group. An Encrypted child of Broadcast parents enables private discussion among subscribers. Ceiling inheritance, eligibility enforcement, and lifecycle coupling operate identically regardless of mode.

**Discovery metadata.** When broadcast contexts register in contexts with discovery outlets (§6.2.2B), the registration metadata includes the context mode. Agents searching for broadcast feeds can filter by mode. DID document `SCPBroadcastContext` service endpoints (§5.14.11) provide direct lookup for broadcast contexts without context queries.

### 6.2.4 Cross-Context Outlet Invocation Saga

§6.2.0 establishes that both contexts' governance mediates a cross-context call; §6.2.0.1 establishes the standing `InterfaceEstablished` consent. This section specifies the per-invocation wire protocol once an interface exists: the call mutates two contexts (the caller's outbound rate-limit/spend plus event log; the target's outlet-session plus event log), so it executes as a saga (§5.15.4).

**Scope.** This governs invocation over an established interface; it does NOT create the interface (§6.2.0.1 governance flow) and does NOT replace synchronous shared-member bridging (§6.2.0) for the colocated case. It is the distinct-actor, atomic-across-the-boundary case.

**`CrossContextOutletInvoke` envelope (JCS)** — the **wire form** (9 fields). The journaled `CrossContextOutletInvocationPrepared` is its **public-metadata projection** (8 fields: `caller_context_id`, `target_context_id`, `caller_did`, `outlet_registration_id`, `ucan_proof_id`, the B-captured `recorded_timestamp_ms`, the B-captured `nonce`, and the B-re-derived `recorded_chain_depth` — see *Recorded timestamp*, *Staged nonce and recorded chain-depth* below) — not a one-for-one mirror. The **caller-asserted** envelope `input`, `chain_depth`, `nonce`, and `timestamp_ms` are NOT trusted as inputs and the caller-asserted forms are NOT journaled: the caller-asserted `timestamp_ms` is used only for the freshness check (never recorded — see *Public-metadata journaling* below), the caller-asserted `chain_depth` is advisory/untrusted (B re-derives its own — see *Chain-depth enforcement* below), and `input` is never journaled. What B DOES stage are: (a) B's durably-staged **copy of the wire `nonce`** — the 16 raw bytes B captures at Prepare-B and will sign into the receipt (see *Staged nonce and recorded chain-depth*); and (b) B's own **re-derived** `recorded_chain_depth` (B's inbound depth = `incoming chain_depth + 1`) plus B's own **captured** `recorded_timestamp_ms` (B's clock at Prepare-B). The staged `nonce` **equals** the caller-supplied wire value — B copies it, it does not generate its own — which is sound because the `nonce` is a public correlation/freshness token (the dedup key, and the join key between the two event-log records per *Dual event-log recording* below), **not** a trust-bearing input; signing B's staged copy is what lets a replayed Commit reproduce the identical receipt. `recorded_chain_depth` and `recorded_timestamp_ms`, by contrast, are **never** the caller-asserted envelope values: B re-derives the depth and reads its own clock, because those two ARE trust-bearing (the depth feeds the §6.2.0 amplification bound; the timestamp dates the provenance edge). All three are staged so that a Commit replayed after a crash — when B no longer holds the wire envelope — reproduces the receipt preimage from durable state. `nonce` and `chain_depth` are public values (not secrets), so staging them keeps the journal non-secret-bearing (see *Public-metadata journaling*).
```
{ "caller_context_id": <64-hex>, "target_context_id": <64-hex>, "caller_did": <string>,
  "outlet_registration_id": <string>, "input": <JSON>, "ucan_proof_id": <string|null>,
  "chain_depth": <int>, "nonce": <16-byte hex>, "timestamp_ms": <int> }
```
**`ucan_proof_id` nullability.** The wire envelope field is `<string|null>`: `null` for an ungated outlet that requires no UCAN proof, or a string (the index into the target's own UCAN store) for a gated one. The wire form is normative; how a binding represents the nullable case in its own types is an implementation concern, not a protocol one.
Normative: (1) **UCAN proof bytes are never in the envelope** — only `ucan_proof_id`, an *index* into the target's own UCAN store (this keeps the envelope and journal non-secret-bearing ⇒ public-metadata journaling only, no §9.4.3 commitment). **`ucan_proof_id` is an index, NOT an authorization.** When the target resolves it, the target MUST re-run the full §7 UCAN validation pipeline against the *carried* `caller_did`: the resolved proof's audience/subject MUST equal `caller_did`, and its capability MUST cover **this** `outlet_registration_id` plus action. "The proof grants the action" is insufficient — without re-binding to `caller_did` plus outlet, a caller could reference a stronger proof in the target's store that was delegated to a *different* principal (a confused-deputy privilege escalation). (2) `input` MUST satisfy the outlet's registered schema structural-specificity floor (§6.2.0, §9.2.1) — degenerate broad-schema input is rejected at Prepare-B.

**Prepare (caller=A, target=B; directional).** Prepare-A stages the caller side: an outbound interface rate-limit decrement (sliding window §6.2.0.2) plus an escrow reservation of the declared per-invocation cost (§19.3) — staged, not applied; it validates that the caller holds `outlet:interface` and is in `OutboundPolicy.allowed_callers`. Prepare-B resolves `ucan_proof_id` and runs the full §7 validation re-bound to `caller_did` plus `outlet_registration_id` (normative (1) above) plus unrevoked, validates `InboundPolicy` (source role, inbound rate, `require_spending_ucan`), validates the `input` schema, and stages an outlet-session reservation; a `Rejected` on any check ⇒ `Aborting`.

**Freshness / anti-replay (normative).** Prepare-B MUST reject the `CrossContextOutletInvoke` unless `timestamp_ms` is within the §9.14 clock-skew tolerance AND `nonce` is absent from a bounded, TTL'd nonce-dedup cache (10,000-entry / oldest-first-eviction discipline, matching §6.2.2; the dedup TTL is set per the *Window relationship* clause below — strictly longer than the skew tolerance, not equal to it). **The target context B — the Prepare-B verifying party — owns this nonce-dedup cache**, keyed by the 16-byte `nonce`: the freshness/replay state lives where the authorization decision is made (B's actor is the authoritative validator, since Prepare-A runs on the caller's actor and cannot authoritatively dedup against B's state). The envelope carries `nonce`/`timestamp_ms` for exactly this purpose: a new saga (a fresh supervisor-minted `SagaId`) carrying a replayed `CrossContextOutletInvoke` is otherwise NOT caught by `SagaId` idempotency — idempotency de-dups re-acks of the *same* saga, not a re-submission of the same invocation under a new saga.

**Window relationship (normative — no coterminous gap).** The nonce-dedup TTL MUST **strictly exceed** the freshness check's §9.14 clock-skew tolerance — it MUST NOT be equal to it. The implementation sets the dedup TTL to **twice** the skew tolerance. Were the two windows coterminous (equal length), a `nonce` recorded at the trailing edge of its freshness window could expire from the dedup cache while a replay carrying a *refreshed* `timestamp_ms` is still inside the freshness window — the replayed invocation would then pass BOTH the freshness gate (fresh timestamp) and the dedup gate (nonce already aged out), defeating exactly-once-per-envelope. With the dedup TTL strictly longer than the skew tolerance, any envelope that passes the freshness check still has its `nonce` remembered, so an in-window replay is always caught. The cache-eviction sizing below is computed against this (longer) dedup TTL window, not the skew tolerance.

**Forward obligation (normative — untrusted transport).** The freshness check binds `timestamp_ms`, which is **caller-asserted** and bound to nothing on its own. In the **co-resident** SDK seam that the current implementation targets, the caller leg is **channel-authenticated** (`caller_did`/`caller_context_id` are the transport-leg identity, never envelope-asserted — see *Cache-eviction bound* above) and there is **no capturable wire envelope**, so exactly-once-per-envelope holds **by construction**: there is no untrusted leg on which a replay can be captured and re-sent. The *Window relationship* clause above bounds, but does not by itself eliminate, a replay that refreshes the asserted timestamp once the original `nonce` has aged out. Therefore, before a future **cross-node child-bridge transport** carries this envelope over an UNTRUSTED link, the asserted `timestamp_ms` MUST be **AUTHENTICATED / BOUND** — either signed by the caller as part of the envelope preimage, or the dedup keyed such that a replay cannot refresh the freshness window — so exactly-once-per-envelope survives an attacker who can capture and re-send the wire form. This is a forward obligation tied to the deferred cross-node work, recorded here as the upstream artifact (mirroring the ADR-049 §3a forward-obligation discipline); the co-resident path satisfies it today by construction.

**Cache-eviction bound (normative).** Because the dedup cache is bounded (10,000 entries, oldest-first eviction), an authorized caller could in principle flood >10,000 distinct fresh nonces to evict a still-within-TTL legitimate nonce and then replay that invocation under a new `SagaId` past the freshness gate. To foreclose this, the implementation MUST size the per-caller §6.2.0.2 rate budget over the dedup TTL window **far below** the cache capacity, so a single caller cannot insert enough entries within the TTL to evict a live nonce. The budget is the binding constraint: each `CrossContextOutletInvoke` reaching Prepare-B consumes one **non-refundable** §6.2.0.2 budget unit (no terminal outcome refunds it — see *Reservation release on every terminal path* below), and §5.15.4 per-participant-context-set serialization forces a single caller's invocations through B sequentially, so the flood cannot be parallelized. Eviction is moreover foreclosed by a **second, independent** gate even in the aggregate-flood case (the dedup cache is a single per-target-B cache shared across all callers, so many distinct authorized callers could in principle co-operate to evict entries faster than any one caller's budget allows): a replayed `CrossContextOutletInvoke` must still pass *Caller authentication* below — `caller_did`/`caller_context_id` are the **channel-authenticated** identity of the transport leg, never envelope-asserted — so a third party cannot present a victim's `caller_did` on its own channel (mismatch ⇒ `Rejected`), and a caller replaying its **own** evicted invocation merely re-spends its own non-refundable budget on a duplicate. The eviction primitive therefore yields no usable replay regardless of aggregate cache pressure. **Sizing relative to the configured ceiling (normative).** The "far below" relationship MUST hold across the **entire configurable** §6.2.0.2 inbound-rate range, not merely the default: the dedup-cache capacity MUST be sized to hold at least every `nonce` admissible within the dedup TTL at the **maximum configured** inbound rate for the interface, times a safety margin (≥ 2×) — equivalently, a context MUST NOT configure an inbound rate whose TTL-window volume approaches the cache capacity. This makes the eviction bound a mechanical function of the configured ceiling, closing the gap where a non-default high rate budget (e.g. a per-interface ceiling whose TTL-window volume exceeds the default cache size) would otherwise let in-budget traffic evict a still-within-TTL `nonce`.

**Recorded timestamp (normative — staged for replay determinism).** The `timestamp_ms` that B records into `OutletInvoked` and signs into the `CrossContextOutletReceipt` is **NOT** the caller-asserted envelope `timestamp_ms` (which is untrusted and used only for the freshness check above). It is `recorded_timestamp_ms` — a wall-clock value B captures **once at Prepare-B** and stages into `CrossContextOutletInvocationPrepared`. Both the Commit-time `OutletInvoked` record and the receipt signature draw `timestamp_ms` from this single staged value, so a Commit replayed after a crash reproduces the identical signed `timestamp_ms` rather than reading a fresh Commit-time clock — a fresh read would make the signed receipt (and B's recorded provenance time) non-deterministic across replays, and would let B sign an attacker-influenced envelope value as authoritative provenance. `recorded_timestamp_ms` is public plan-metadata, so staging it keeps the journal non-secret-bearing.

**Staged nonce and recorded chain-depth (normative — staged for replay determinism).** The `CrossContextOutletReceipt` signature preimage covers `RawBytes16(nonce)` and `U8(chain_depth)` (see *Receipt / response return path* below). Both MUST be drawn from staged state, never re-read from the wire envelope at Commit time — because on a Commit replayed after a crash B no longer holds the envelope, and a signed value that cannot be reproduced from durable state breaks the by-`SagaId` "replayed Commit re-signs the identical receipt preimage, byte-for-byte" guarantee (the same replay-determinism failure mode `recorded_timestamp_ms` is staged to prevent). Therefore, at Prepare-B, B captures both into `CrossContextOutletInvocationPrepared`:

- **`nonce`** — the 16 raw bytes B captures from the invocation at Prepare-B and will sign into the receipt. B stages the invocation `nonce` so a replayed Commit re-signs the same value. (This is B's captured copy of the public `nonce`, not a secret; it is the same value the auditor uses to join the two event-log records, *Dual event-log recording* below.)
- **`recorded_chain_depth`** — B's OWN re-derived inbound depth = `incoming chain_depth + 1` (the value B records into `OutletInvoked` and signs into the receipt per the *Chain-depth enforcement* clause), explicitly **NOT** the caller-asserted envelope `chain_depth`. Staging B's re-derived value means a replayed Commit reproduces the identical signed depth rather than re-reading the (discarded, and in any case untrusted) envelope value.

Both the Commit-time `OutletInvoked` record and the receipt signature draw `nonce`/`chain_depth` from these single staged values, identical to how `timestamp_ms` is drawn from the staged `recorded_timestamp_ms`. `nonce` and `recorded_chain_depth` are public plan-metadata, so staging them keeps the journal non-secret-bearing.

**Caller authentication (normative).** `caller_did` and `caller_context_id` MUST be the channel-authenticated identity of the transport leg (the shared-member SDK-seam membership, or child-bridge parentage, per §6.2.0) — not merely envelope-asserted fields. A mismatch between the asserted `caller_did`/`caller_context_id` and the authenticated channel ⇒ `Rejected`. All `InboundPolicy` checks and the `OutletInvoked` provenance record MUST evaluate the channel-authenticated identity, never the attacker-asserted envelope fields.

**Target-context binding (normative).** `target_context_id` MUST equal the `target_context` of the established `InterfaceEstablished`/`InterfaceOffer` (§6.2.0.1) the invocation rides — i.e. B's own context, the context in which B will execute the outlet. B MUST verify that the asserted `target_context_id` equals the established interface's `target_context`, and reject (⇒ `Rejected`) otherwise. Because `outlet_registration_id` is a context-LOCAL identifier (it indexes B's own outlet registry), the same `outlet_registration_id` can exist in two contexts B₁/B₂ that the same target DID/key controls; without binding the executing context into the call (and into the signed receipt, below), a receipt produced in B₁ could be presented as provenance for an invocation A believed targeted B₂. The target-context binding forecloses that mis-attribution, the symmetric case of the `caller_did`-axis confused-deputy defense (signing `caller_context_id` alone would not pin which member made the call; signing `caller_context_id` alone — without `target_context_id` — would not pin which context executed it). `target_context_id` is ALWAYS the raw 32-byte context-id digest — 64-hex on the wire, `Fixed32` in the signature preimage — the same id-form rule the *`caller_context_id` id-form* clause below states for `caller_context_id` (never a `"standing-"`-prefixed string).

**Chain-depth enforcement (normative).** Prepare-B MUST reject the invocation if `chain_depth >= ContextParams::max_chain_depth` (§6.2.0). The caller-asserted `chain_depth` in the `CrossContextOutletInvoke` envelope is **advisory and untrusted** and is used by Prepare-B for exactly two things: the `>= max_chain_depth` reject above, and under-report detection (Prepare-B MAY additionally reject if the asserted depth is implausibly low for the channel-authenticated caller — but cannot in general verify another context's claimed inbound depth, so this is a heuristic, not a guarantee). The value B records and propagates is **B's own**, not the envelope's:

- **B records its OWN inbound depth.** The `chain_depth` written into `OutletInvoked` (under Commit-B) is the depth B derives for *this* invocation — `incoming chain_depth + 1` — bound to the channel-authenticated caller established by the *Caller authentication* clause above. This becomes the depth B has recorded for the invocation it is now executing.
- **Onward calls are B-stamped, not envelope-derived.** When an outlet executing under Commit-B triggers an onward cross-context outlet call, that onward call's `chain_depth` MUST be set by **B** to **(the `chain_depth` B recorded for the invocation currently executing) + 1** — derived from B's OWN channel-authenticated, recorded inbound depth, NOT from any value the executing outlet supplies. A calling context therefore cannot reset depth on a chain it does not originate: each honest callee re-derives `+1` from what *it* received and B-stamps its own onward calls, so depth is monotonic across every hop B controls.

**Honest bound (no over-claim).** A target cannot independently verify a *different* context's claimed inbound depth, so a malicious calling context CAN under-report `chain_depth` on its OWN single outbound edge — shaving at most the one hop it controls. It cannot compound this across hops: every honest callee re-derives `+1` from the depth it recorded and B-stamps its own onward calls, so a single under-report does not propagate. Amplification is therefore bounded **per-honest-hop** by `max_chain_depth`, and ultimately by the per-caller §6.2.0.2 rate budget plus per-context-pair saga gating — NOT solely by `max_chain_depth`, and NOT "preserved across every hop" (which would falsely assume every hop is honest).

**Reservation release on every terminal path (anti-griefing, normative).** Prepare-A's rate-limit decrement and escrow reservation, and Prepare-B's outlet-session reservation, MUST be released on **every** terminal outcome — `Aborted`, Prepare timeout, operation panic, supervisor cancellation — using an RAII drop-on-not-commit reservation guard **analogous to §5.15.7's send-sequence reservation** (cited as pattern precedent only: §5.15.7 governs send-sequences specifically; *this clause* is the normative authority for outlet-invoke reservations). In Rust: a reservation guard; in other languages: try/finally covering every terminal path. A Prepare-A that times out at Prepare-B counts against the *initiator's* per-caller §6.2.0.2 budget as a **consumed** call (so an authorized caller who stalls sagas to grief the interface burns its own quota — not a free retry). Combined with per-context-pair saga gating (so one abandoned saga does not block the whole interface), this forecloses escrow/rate-limit griefing. A Prepare-phase failure caused by a participant actor being unavailable to complete the Prepare exchange (reliably: its inbox is closed or the actor terminated) is likewise a retryable **clean abort** — neither side committed, the same all-or-nothing guarantee as a Prepare timeout — and is surfaced as a typed *retryable* saga abort (a transient back-off condition) distinct from a permanent rejection. A transiently-saturated-but-open mailbox is a separate timeout-tuning concern: while the inner send timeout equals the phase timeout it may instead surface as a generic Prepare-timeout abort rather than this retryable terminal.

**Commit.** Commit B then A. **B executes the outlet** under its own governance (the generic executor cannot cross the mailbox per ADR-049 §3, so Commit *triggers* execution plus captures the result), applies the staged rate-limit/session, and records `OutletInvoked` (caller ctx id, B's own `target_context_id` — the verified executing context per the *Target-context binding* clause above, caller DID, the **target-re-derived** `chain_depth` = `incoming chain_depth + 1` per the chain-depth enforcement clause above — never the caller-asserted value, and the staged `recorded_timestamp_ms` captured at Prepare-B — never a fresh Commit-time clock read, per the *Recorded timestamp* clause above). A captures the returned output, settles escrow (§19.2.2), applies the outbound decrement, and records `CrossContextOutletInvoked` referencing B's ctx id plus the same `nonce`. Idempotent by `SagaId` on both sides. **Exactly-once execution with durable output capture (normative).** B executes the outlet **exactly once**; the captured output is persisted durably keyed by `SagaId`, so a **replayed Commit re-emits the stored output and re-signs the identical receipt preimage, never re-invoking the outlet**. Re-invoking a non-deterministic or side-effecting outlet on replay would produce a different `output_hash` and therefore a non-deterministic signed receipt, breaking the by-`SagaId` "replayed Commit is a no-op" guarantee; the durable, `SagaId`-keyed output capture is what makes the replayed Commit reproduce the original receipt byte-for-byte. **`SagaId`-idempotent event-log append (normative).** B's `OutletInvoked` event-log append is likewise `SagaId`-idempotent: the append is keyed by `SagaId`, so a replayed Commit **re-acks the existing append and returns the SAME `outlet_invoked_event_id`** rather than minting a new one. This is required for receipt reproducibility — `outlet_invoked_event_id` is a signed preimage field (*Receipt / response return path* below), so a replayed Commit that minted a fresh event id would sign a different preimage and produce a divergent receipt, the same non-repudiation defect the staged `nonce`/`recorded_chain_depth`/`recorded_timestamp_ms` foreclose. Every signed preimage field is thus reproducible on replay from staged or `SagaId`-keyed durable state.

**Crash recovery (§17.16.4).** On restart, §5.15.4 replay re-drives unresolved entries per §17.16.4: a **Commit-in-progress** journal ⇒ re-send Commit to B and A, each idempotent by `SagaId` (B re-acks the existing `OutletInvoked` append and re-emits the stored output, **never re-invoking the outlet**; A re-acks its `CrossContextOutletInvoked` append and re-settles escrow as a no-op); a **Prepare-in-progress** journal ⇒ abort the Prepared actor (release the staged rate/escrow/session reservations via the RAII guard) and discard, never re-Prepare; **Pre-Prepare** ⇒ discard. The initiator retries fresh.

**Durably-staged caller deduction — Prepare-in-progress recovery does NOT unconditionally discard (normative).** The *Prepare-in-progress ⇒ discard* rule above describes the in-process LIVE abort path, where the RAII drop-on-not-commit guard is still resident and releases the staged reservations. After a **crash-restart**, that guard is gone, and for a cross-context saga the caller-side deduction is **not** in-memory: Prepare-A **durably** persists the caller's velocity/budget/hard-rate-limit deduction **and** its `CallerReservationRecord` (the only durable handle for reversing that deduction) **BEFORE** the FSM journals the `PreparingB` entry. A crash anywhere in that window can therefore leave a `PreparingA` **or** `PreparingB` journal over a **LIVE durable caller reservation**. Recovery in this case MUST NOT simply abort-and-discard (which marks the journal terminal-`Aborted`, asserting "fully compensated"): doing so would **strand the durable deduction + record forever**, because the §17.16.4 sweep re-drives only NON-terminal journals — a permanent, silent caller over-charge plus an escrow leak. Instead, Prepare-in-progress recovery for a saga whose caller deduction was durably staged:
- **reverses** the caller's LOCAL economy (velocity/budget/hard-rate-limit and the escrow void) from the durable `CallerReservationRecord` — the same reversal the LIVE abort path performs — and **confirms delivery** of that reversal to the caller context;
- writes **terminal-`Aborted` ONLY** on a **confirmed reversal** (the caller context acknowledged `SettledOrAbsent`) **or** on a **permanently-deleted caller context** (its reservation record died with the context, so there is nothing to reverse and the saga is reaped rather than looping forever);
- **otherwise leaves the journal NON-terminal** (at `PreparingB`) so the NEXT process start's restore-then-replay pass re-drives the reversal. A crash leaves the entry non-terminal; recovery runs **once per process start**, after the restore leg has made the caller resident — there is NO separate within-restart post-restore sweep (§17.16.4: reconciliation runs once, after restore, in the same startup pass; the only "later sweep" is a subsequent restart). On the NORMAL pass the caller is restored first, so the reversal is delivered in-pass and the entry reaches terminal-`Aborted`; the entry is carried forward only in the genuinely-undeliverable case (the caller context failed to restore, or its persistence existence cannot be confirmed). It MUST NOT assert "fully compensated" while a caller refund is still outstanding.

This contract covers **both** `PreparingA` and `PreparingB` journals (a `PreparingA` xctx entry carries the same caller-provenance participant triple, so it routes through the identical record-keyed reversal-and-confirm path). It does **not** alter the LIVE (non-crash) abort path: there the RAII reservation guard remains authoritative and releases the staged reservations directly; the durable-record reversal described here is the **crash-only** fallback for when that guard no longer exists. A non-cross-context Prepare-in-progress entry (no durably-staged caller deduction) has nothing to reverse and discards as before.

**Transport leg.** Over the established interface's transport (the shared-member local SDK seam, or the multi-parent child bridge), never a new relay primitive. Phase messages are §5.15.3 observers gated behind the journal's durable per-phase ack.

**Receipt / response return path.** `CrossContextOutletReceipt` carries `caller_context_id`, `target_context_id`, `caller_did`, the same `nonce`, `outlet_registration_id`, the output (as its JCS-canonical bytes, per the *Output canonicalization obligation* below), the target's `OutletInvoked` event id, `chain_depth`, `timestamp_ms`, and the target's Ed25519 signature (the field order matches the signature preimage below — see §9.5.1: field order is normative — with the output slot carrying the JCS-canonical output BYTES that the preimage hashes into `output_hash = SHA-256(output)`, NOT the 32-byte `output_hash` digest itself; the verifier needs those bytes to recompute the hash, per the *Output canonicalization obligation* below). The receipt's `chain_depth` (and the `U8(chain_depth)` field of the signature preimage) is **B's target-re-derived depth = `incoming chain_depth + 1`, identical to the value B wrote into `OutletInvoked`, NEVER the caller-asserted envelope value** — signing the untrusted incoming value would defeat the binding, since the receipt's purpose is to make the §6.2.0 chain-depth guarantee non-repudiable. Likewise, the receipt's `timestamp_ms` (the `U64(timestamp_ms)` preimage field) is **B's Prepare-B capture instant — the staged `recorded_timestamp_ms`, the moment B admitted the invocation — NOT the caller's send time**; the caller-asserted envelope `timestamp_ms` is consumed only by the freshness check and is never recorded or signed, so a receipt consumer MUST read the receipt's `timestamp_ms` as "when the target accepted the call," identical to the timestamp B wrote into `OutletInvoked`. Every field of the signature preimage is carried on the receipt, so a verifier can reconstruct the preimage from the receipt alone — the receipt is **self-verifying**. **Signer authorization (normative).** Self-verifiability establishes only that the carried fields are internally consistent and signed by *some* key; a receipt consumer — an auditor, or A presenting the receipt as provenance — MUST additionally confirm the signing key is the **Active Signing Key authorized to act for `target_context_id`**, resolved via that context's membership/governance (§3, §7), not merely that the Ed25519 signature is internally valid. Without this binding, a key that does not in fact control `target_context_id` could sign a receipt naming it. The signature preimage is the **§9.5.1 canonical hash construction** (field-enumerated, length-prefixed — NOT a raw concatenation, which would be splice-ambiguous because `outlet_registration_id` and `caller_did` are variable-length strings):
```
sig = Ed25519_sign(target,
  canonical_hash("SCP-XCTX-RECEIPT-V1:", &[
    Fixed32(caller_context_id),            // 32 raw bytes
    Fixed32(target_context_id),            // 32 raw bytes — B's executing context
    VarBytes(caller_did.bytes),            // 4-byte BE len prefix + bytes
    RawBytes16(nonce),                     // 16 raw bytes, fixed
    VarBytes(outlet_registration_id.bytes),  // 4-byte BE len prefix + bytes
    Fixed32(output_hash),                  // 32 raw digest bytes (NOT 64-hex)
    VarBytes(outlet_invoked_event_id.bytes), // 4-byte BE len prefix + bytes
    U8(chain_depth),
    U64(timestamp_ms),
  ]))
```
**`caller_context_id` id-form (normative).** `caller_context_id` is ALWAYS the raw 32-byte context-id digest — hex-encoded (64-hex) on the wire envelope, `Fixed32` (32 raw bytes) in the signature preimage. For a standing-pair caller this is the `derived_context_id` (the raw 32-byte digest, §5.15.8), **NOT** the `"standing-"`-prefixed canonical/display string: §5.15.8 defines `derived_context_id: [u8;32]` as the raw digest *before* the `"standing-"` prefix and hex, so it is exactly the 32 bytes `Fixed32(caller_context_id)` encodes. A reader MUST NOT place the prefixed `"standing-" + 64-hex` string into `caller_context_id` — `Fixed32` cannot encode it, and the wire field is the 64-hex of the raw digest, never the prefixed form. `target_context_id` obeys the identical id-form rule: raw 32-byte digest, 64-hex on the wire, `Fixed32` in the preimage, never a `"standing-"`-prefixed string.

`output_hash` is the 32 **raw** digest bytes of `SHA-256(jcs::to_string(output).into_bytes())` — this keeps the caller log free of a large or sensitive payload while preserving a verifiable link. **Output canonicalization obligation (normative — self-verifiability requires it).** The receipt carries the output as its **JCS-canonical bytes** — the exact serialization the signer hashed (`jcs::to_string(output).into_bytes()`) — so the verifier recomputes `output_hash = SHA-256(carried_output_bytes)` **directly, with no re-canonicalization step**. The receipt is only self-verifying if the carried output bytes ARE the hashed preimage: were the receipt to carry non-JCS (e.g. re-serialized or pretty-printed) output, the verifier would have to re-canonicalize identically to reproduce `output_hash`, and any serialization divergence would fail verification on an otherwise-valid receipt. Carrying the JCS-canonical bytes removes that hidden re-canonicalization dependency. Binding `caller_did` into the preimage pins the principal the receipt is issued to (a context can have multiple member DIDs, so signing `caller_context_id` alone would not pin *which* member made the call — the confused-deputy defense binds to `caller_did`, so the receipt MUST too). Binding `target_context_id` pins **which context B executed the outlet in**: `outlet_registration_id` is context-LOCAL (it indexes B's own registry), so the same id can exist in two contexts B₁/B₂ controlled by the same target DID/key; without signing `target_context_id`, a receipt produced in B₁ could be replayed as provenance for an invocation A believed targeted B₂ (a target-axis mis-attribution / repudiation defect — the symmetric case of the `caller_did` confused-deputy binding). The *Target-context binding* clause above requires B to verify the asserted `target_context_id` equals the established interface's `target_context` before executing; signing it makes that binding non-repudiable on the receipt. Binding `outlet_invoked_event_id` makes the link from the receipt to the target's executed-call event log entry unforgeable (carrying it unsigned would let an attacker re-point the receipt at a different event). Covering `chain_depth` plus `timestamp_ms` makes the provenance edge non-repudiable on depth and time (the §6.2.0 chain-depth guarantee depends on it). All three of the signed `nonce`, `chain_depth`, and `timestamp_ms` are drawn from staged state, never re-read from the (discarded) wire envelope at Commit time: the signed `nonce` is the staged `nonce`, the signed `chain_depth` is the staged `recorded_chain_depth` (B's re-derived inbound depth = `incoming chain_depth + 1`, never the caller-asserted envelope value), and the signed `timestamp_ms` is the staged `recorded_timestamp_ms` — each identical to the value written into `OutletInvoked` (per the *Staged nonce and recorded chain-depth* and *Recorded timestamp* clauses), so a replayed Commit re-signs the same preimage byte-for-byte. `SCP-XCTX-RECEIPT-V1:` is a new, first-version separator, so the full field set is fixed here with no compatibility concern. **Integer field encoding (normative).** The `U8(chain_depth)` and `U64(timestamp_ms)` preimage terms (and the `<int>` wire forms that feed them) are exact unsigned integers bounded well below 2^53 — inside JCS's exact-integer range (RFC 8785), so they round-trip losslessly; implementations MUST parse and encode these as fixed-width unsigned integers (`u8`/`u64` respectively — `chain_depth` is a `u8`, matching `ProvenanceRecord.chain_depth` and the `[1, 255]` `max_chain_depth` range in §6.2.0 / §24.4), never as IEEE-754 doubles, so signer and verifier feed the byte-identical value to each preimage term.

**Dual event-log recording (normative).** The call is recorded in **both** logs as **distinct types**: B = `OutletInvoked` (executed), A = `CrossContextOutletInvoked` (called out); both share the `nonce` (an auditor joins them into one provenance edge). All-or-nothing: `Committed` ⇒ both records; `Aborted` ⇒ neither. **`NeedsRepair` ⇒ both sides MUST emit a signed `CrossContextDivergenceMarker`** (into each available log, or a supervisor-level repair journal if one side is unreachable) recording which side committed, the `SagaId`, the `nonce`, and the committed-side event id. A silent one-sided log is a repudiation primitive (B executed and charged, A denies the call, or the reverse); the signed marker makes the divergence durably auditable and resolvable by operator repair, surfaced as a typed saga error.

**`CrossContextDivergenceMarker` signature preimage (normative).** The signed divergence marker carries `saga_id`, `nonce`, `committed_side`, `committed_event_id`, and the emitting side's Ed25519 signature. Its signature preimage is the **§9.5.1 canonical hash construction** (field-enumerated, length-prefixed — NOT a raw concatenation, which would be splice-ambiguous because `saga_id` and `committed_event_id` are variable-length strings), with its own first-version domain separator (distinct from `SCP-XCTX-RECEIPT-V1:` so a receipt signature can never be replayed as a divergence-marker signature, or vice-versa):

```
sig = Ed25519_sign(emitter,
  canonical_hash("SCP-XCTX-DIVERGENCE-V1:", &[
    VarBytes(saga_id.bytes),               // 4-byte BE len prefix + bytes
    RawBytes16(nonce),                     // 16 raw bytes, fixed
    U8(committed_side.tag()),              // Caller = 0, Target = 1
    VarBytes(committed_event_id.bytes),    // 4-byte BE len prefix + bytes
  ]))
```

**`committed_side` tag mapping (normative).** `committed_side` records which leg of the saga committed when the other did not (the divergence the marker makes auditable). Its `U8` preimage tag is a fixed, versioned enumeration: **`Caller = 0`, `Target = 1`** — the same tag the wire form carries. The mapping is fixed by this (first) version of the `SCP-XCTX-DIVERGENCE-V1:` separator; a future tag addition or remap requires a new separator version, so signer and verifier feed the byte-identical `U8` to the preimage. `committed_event_id` is the committed side's event-log entry id (B's `OutletInvoked` event id when `Target` committed, A's `CrossContextOutletInvoked` event id when `Caller` committed) — the same `nonce`-joined provenance edge the dual event-log recording above pins, now signed so the one-sided commit is non-repudiable. `SCP-XCTX-DIVERGENCE-V1:` is a new, first-version separator (its §9.18.2 separator-registry row already exists), so the full field set is fixed here with no compatibility concern.

**`NeedsRepair` reservation semantics (normative — concurrency slot and economic reservation release differently).** On a `NeedsRepair` outcome the **concurrency-gating** reservation (the participant-context-set slot, §5.15.4) is **released** — consistent with §5.15.4, so a diverged-but-unresolved outlet invoke does not wedge unrelated sagas on either context. The **escrow/rate-limit** (economic) reservation is **not** governed by the RAII drop-on-not-commit guard in this case: because the operation may have **partially committed** (B executed and charged while A's settle did not land, or the reverse), the escrow settlement is resolved by the signed `CrossContextDivergenceMarker` plus operator repair (which reconciles which side committed and settles escrow accordingly), NOT auto-voided on the `NeedsRepair` transition. The concurrency reservation and the economic reservation therefore have **distinct release semantics on `NeedsRepair`**: the concurrency slot releases immediately so no unrelated saga is blocked, while the economic reservation is settled by the divergence-marker + operator-repair path — and neither leaves the slot wedged. (This is the only path where the two reservation kinds diverge; on every *terminal* non-repair outcome the RAII guard releases both, per the *Reservation release on every terminal path* clause above.)

**Initiation consumes budget; no terminal outcome refunds it (anti-griefing, normative — no attribution oracle).** Initiating a cross-context outlet saga consumes **one call against the initiator's per-caller §6.2.0.2 budget at initiation**, and **NO** non-`Committed` terminal outcome — `Aborted`, Prepare timeout, supervisor cancellation, OR `NeedsRepair` — refunds it. There is therefore **no attribution decision** to make and no free-retry complement: the rule does NOT depend on deciding whether a `NeedsRepair` (or any other failure) is "the initiator's fault," "B's fault," or unattributable. A caller that drives sagas into `NeedsRepair` — by whatever leg faults, including deliberately steering the Commit failure onto B's leg — burns its own quota **per initiation regardless of which side faulted**, so self-inducing divergence to tie up escrow and operator attention is rate-bounded by the caller's own budget. This is the same at-initiation consumption that makes a Prepare timeout a **consumed** call (per the *Reservation release on every terminal path* clause): both are instances of the single rule "initiation consumes; nothing refunds." **Escrow settlement and rate-budget consumption are orthogonal.** The escrow stays reserved pending the signed `CrossContextDivergenceMarker` plus operator repair — auto-voiding a possibly-partially-committed escrow on `NeedsRepair` would itself be a free-execution exploit (B may have executed and charged), so the escrow is **not** released on this transition (only the concurrency slot is released, per *`NeedsRepair` reservation semantics* above, consistent with §5.15.4). The divergence marker plus operator repair settles the **escrow** (the economic outcome); the at-initiation budget consumption bounds the **rate** of initiation — neither depends on deciding "whose fault."

**Public-metadata journaling.** The journal records only the public `CrossContextOutletInvocationPrepared` (caller ctx id, `target_context_id`, caller DID, `outlet_registration_id`, `ucan_proof_id`, the B-captured `recorded_timestamp_ms`, the B-captured `nonce`, and the B-re-derived `recorded_chain_depth`) — never UCAN bytes, never input/output. The journaled values are B-controlled: B's clock value `recorded_timestamp_ms` (NOT the caller-asserted send-time `timestamp_ms`, which serves only the freshness check), B's **re-derived** `recorded_chain_depth` (NOT the caller-asserted advisory `chain_depth`), and B's **staged copy of the wire `nonce`** — the same 16 bytes the caller supplied (equal by design, since the `nonce` is a public correlation/dedup token, not a trust-bearing input: B both consults it against the dedup cache and stages this copy for the receipt and journal). For the timestamp and depth the journaled value genuinely differs from the caller-asserted envelope value; for the nonce the journaled value equals the wire value but is staged from B's own captured copy so a replayed Commit reproduces it from durable state. All eight journaled fields are public, non-secret-bearing values — `nonce` and `chain_depth` are public, not secrets — so the journal carries no bearer material; `mark_resolved(secret_bearing=false)`.

Cross-refs: §6.2.0, §6.2.0.1, §5.15.4, §9.2.1, ADR-049 §3a (FFI Saga Surface).

## 6.3 The Human as Bridge

The human coordinates across their own contexts locally. Their local agent orchestration — unconstrained by the protocol — handles cross-context intelligence. For the human's own agents, the human remains the bridge — local coordination across their own contexts requires no network-level mechanism.

Two protocol-level mechanisms formalize cross-context relationships: outlet interfaces (§6.2) for asymmetric service-style interactions, and multi-parent child contexts (§5.13) for symmetric collaboration. Both require governance consent from all involved contexts. The human's local coordination handles everything that doesn't need to be on the network — and when a cross-context relationship should be visible, governed, and persistent, a multi-parent child context makes the bridge structural rather than implicit.

**Two-tier interaction model.** The protocol provides two tiers of cross-agent communication with different overhead appropriate to different risk profiles:

- **Shared contexts** (bilateral or multi-party) for lightweight, symmetric, low-ceremony communication. A message in a shared context is encrypt-send-decrypt with no per-message governance overhead. All the protocol's trust and encryption properties apply. This is the equivalent of a text message.
- **Outlet interfaces** for formal, structured, asymmetric cross-context data exchange. Full governance mediation on both sides, schema-declared data flow, audit logging, rate limiting, provenance attachment. This is the equivalent of an API call.

Agents use whichever tier fits the interaction. Lightweight coordination ("are you available?", "quick update") flows through shared contexts. Formal cross-context data queries flow through outlet interfaces. Both are governed; the difference is in ceremony and auditability per interaction.
