# 5. Contexts

## 5.1 Definition

All interaction happens within contexts. There is no concept of off-context communication at the protocol level. A context is a bounded, governed space — a cryptographic entity with its own key material, event log (append-only Merkle tree), governance model, membership roster, and capability ceiling. Contexts operate in one of two modes: **Encrypted** (one MLS group per context, sender-side keys, full forward secrecy) or **Broadcast** (per-author broadcast keys, no MLS, mandatory subscriber registration). The mode is set at creation and is immutable. A group chat is a context. A collaborative quest is a context. A generated Discord alternative is a context. DMs are a two-party context. An entire app's backend is a context (or set of contexts).

**Contexts are spaces, not actors.** They do not initiate, do not act, and have no agency. They hold the rules, the keys, and the audit trail. Agents (always bound to humans, §4) do the acting within them. Tools (§5.4) do the computing within them. The context itself is passive infrastructure.

**Contexts are runtime objects, not infrastructure to deploy.** Creating a context is a runtime operation (~5-15ms local computation, ~200ms wall clock with network — see §5.12.4). Contexts are created, used, and destroyed during normal application operation. They survive process restarts (state is persisted) but are created as fluidly as opening a connection.

**Contexts are where apps live.** What people experience as "an app" is a composite: a context (or set of contexts) + members + tools + data (§8.1). Long-lived contexts with no TTL host persistent applications — games, workspaces, social platforms. Ephemeral contexts with TTL host bounded tasks. The context is the app's lifecycle boundary. Protocol state (membership, roles, trust) is portable and survives app death; app state is the app's concern (§8.3).

**Every context contains:** a capability ceiling (§5.3), roles with permission sets (§5.5), a governance model (§5.9), tools (§5.4), an optional TTL (§5.10), a memory scope (§5.11), and transparent metadata visible before opt-in (§5.7). These are all declared at creation. Contexts may be created from well-known templates (§5.12) for common patterns or from explicit parameters. Contexts can have parent-child relationships (§5.13) for sub-spaces and governed cross-context bridges.

**Two protocol-level mechanisms allow information to cross context boundaries:** tool interfaces (§6.2) for asymmetric, structured, request/response interactions, and multi-parent child contexts (§5.13) for symmetric collaboration. Both require governance consent from all involved contexts. Agent isolation is absolute — no agent instance spans contexts (§6.1).

## 5.2 Creation

Contexts are created by accountable identities only. Anonymous or unbound entities cannot create contexts. Creating a context is an act of social infrastructure — you're defining a space where autonomous software operates on people. Contexts may be created from well-known templates (§5.12) for common patterns, or from explicit parameters for bespoke configurations. Both paths produce identical contexts; templates are the fast path.

Context creation branches on `ContextMode` (§5.14). Encrypted contexts create an MLS group during the `Creating → Active` transition. Broadcast contexts skip MLS group creation and instead initialize the creator's broadcast key (epoch 0). Both modes produce a context with an event log, governance model, roles, and transport subscriptions — the mode determines the encryption pipeline, not the context's structural properties.

### 5.2.1 Context Creation Failure Handling

Context creation is a multi-step operation that can fail at any point. The protocol requires **atomic creation semantics** — a context either fully exists or does not exist at all. No partial contexts are observable by any participant.

**Failure points and rollback behavior:**

| Step | Operation | Failure rollback |
|------|-----------|-----------------|
| 1 | Governance validation (ceiling policy, roles, template conformance) | No state created. Return error to creator. |
| 2 | Context ID generation and local state initialization | Destroy local state. Return error. |
| 3 | MLS group creation (Encrypted mode) or broadcast key initialization (Broadcast mode) | Destroy MLS group state / broadcast key material. Destroy local state. Return error. |
| 4 | Event log initialization (first entry: `Created`) | Destroy event log, MLS group state / broadcast key material, local state. Return error. |
| 5 | UCAN minting for creator's initial capabilities | Destroy minted tokens, event log, MLS group state / broadcast key material, local state. Return error. |
| 6 | Relay registration (transport subscription, metadata publication) | Issue best-effort DELETE for any published relay messages. Destroy all local state (UCANs, event log, MLS group / broadcast keys, context state). Return error. |
| 7 | Initial member addition (if creation includes members beyond creator) | Issue MLS remove for added members, relay DELETE for membership messages. Destroy all local state. Return error. |

**Rollback ordering.** Rollback proceeds in reverse creation order. Each step's rollback is idempotent — repeated rollback of the same step produces no additional side effects.

**Relay cleanup is best-effort.** Relays are untrusted infrastructure and cannot be forced to delete published messages. However, any orphaned relay messages from a failed creation are encrypted with destroyed key material and cannot be decrypted. Orphaned blobs consume relay storage and expose routing metadata; the SDK SHOULD track failed creation cleanup attempts and retry on next relay connection. Relay compliance with deletion requests is tracked as part of relay reliability scoring (§9.9.2).

**Creator observability.** On failure, the creator receives an error indicating the failure point (e.g., `ContextCreationFailed::RelayRegistration`). No `ContextCreated` event is emitted. No other participant observes any state from the failed creation — the context ID is not reusable (UUIDs are unique), but no context with that ID exists in the protocol.

**Retry semantics.** Creation is safe to retry after failure. Each retry generates a new context ID and fresh key material. The failed creation's context ID is abandoned — there is no "resume" mechanism for partially created contexts.

**Child context creation failure.** For child contexts (§5.13.3), creation failure after governance approval from one or more parents does not consume the approval. Parent governance proposals for the failed child are marked as expired (not executed), and new proposals are required for a retry. This prevents a failure in one parent's relay from silently consuming another parent's governance approval.

## 5.3 Capability Ceiling

Every context declares a capability ceiling at creation: the maximum set of things that can happen in this space. This ceiling bounds what outlets can do, what roles can grant, and what agents can exercise. Standard capability categories include:

- **`messaging`** — text and structured data exchange
- **`outlet:query`** — invoking context-registered Query outlets (§5.4.2)
- **`outlet:call`** — invoking context-registered Action outlets (§5.4.2)
- **`media:voice`** — real-time voice communication (§10.9.1)
- **`media:video`** — real-time video communication (§10.9.1)
- **`media:screen_share`** — screen sharing (§10.9.1)
- **`bridging`** — bridge connector participation (§12)
- **`outlet:interface`** — cross-context outlet interface exposure (§6.2)
- **`context:child:create`** — creating child contexts (§5.13)
- **`member:ban`** — governance-level member removal (ban/unban). Gates whether governance can execute `RevokeAccess` / `RestoreAccess` against members (§5.9). Without this capability in the ceiling, governance cannot ban members regardless of governance model.

Media capabilities (`media:*`) enable the delegated media transport model (§10.9.1) where the context establishes identity, trust, and governance while media flows over WebRTC/DTLS-SRTP. A context without media capabilities in its ceiling cannot initiate voice or video sessions regardless of participant roles.

Capability categories apply uniformly across context modes. `messages:read` and `messages:write` retain the same abstract meaning in both Encrypted and Broadcast modes — the `ContextMode` determines the encryption pipeline, not the capability semantics. A `messages:write` UCAN in an Encrypted context authorizes MLS-encrypted message sending; the same capability in a Broadcast context authorizes broadcast-key-encrypted publishing.

Every context also declares a **ceiling policy** at creation — whether the ceiling can change and how. The ceiling policy itself is immutable (locked at creation, cannot be changed). Two policies are available:

- **`immutable`** (default for all well-known templates): Ceiling cannot change after creation. To expand capabilities, create a new context and migrate (§5.11A). Strongest security guarantee — members know the ceiling they opted into is permanent.
- **`governed`**: Ceiling can be modified through the context's governance model (admin, multi-sig, consensus). Changes are logged in the event log and visible to all members before taking effect. Members who joined under a narrower ceiling are notified and may leave before the expansion takes effect.

The ceiling policy is visible in context metadata (§5.7) before opt-in. A prospective member sees both the current ceiling and the policy governing changes.

**Economic policy is orthogonal to capability ceiling.** Ceiling governs what CAN happen; economic policy (§19.3) governs what it COSTS. Economic policy is not a ceiling category — it does not restrict or expand what actions are available, only what they cost.

### 5.3.1 Exhaustive Capability Categories

The following is the complete enumeration of capability categories available for context ceiling declarations. These are the ONLY valid values in a ceiling array. SDKs MUST reject unrecognized capability categories at context creation time.

| Category | Description | Gated by |
|----------|-------------|----------|
| `messages:read` | Read messages in the context | Role permission |
| `messages:write` | Send messages to the context | Role permission |
| `outlet:register` | Register new outlets in the context | Role permission |
| `outlet:query:*` | Invoke any registered Query outlet (§5.4.2) | Role permission |
| `outlet:query:{outlet_id}` | Invoke a specific Query outlet (parameterized) | Role permission |
| `outlet:call:*` | Invoke any registered Action outlet (§5.4.2) | Role permission |
| `outlet:call:{outlet_id}` | Invoke a specific Action outlet (parameterized) | Role permission |
| `member:invite` | Invite new members to the context | Role permission |
| `member:remove` | Remove members from the context | Role permission + governance |
| `member:ban` | Ban members (revoke read access) | Role permission + governance |
| `role:assign` | Assign or change member roles | Role permission + governance |
| `media:voice` | Real-time voice communication (§10.9.1) | Role permission |
| `media:video` | Real-time video communication (§10.9.1) | Role permission |
| `media:screen_share` | Screen sharing (§10.9.1) | Role permission |
| `bridging` | Bridge connector participation (§12) | Role permission + governance |
| `outlet:interface` | Cross-context outlet interface exposure (§6.2) | Role permission |
| `context:child:create` | Create child contexts (§5.13) | Role permission |
| `governance:propose` | Submit governance proposals (§5.9) | Role permission |
| `governance:vote` | Vote on governance proposals (§5.9) | Role permission |
| `context:close` | Close context permanently (§5.4) | Role permission + governance |
| `metadata:edit` | Edit context operational metadata (§5.7) | Role permission + governance |

**Parameterized categories.** `outlet:query:{outlet_id}` and `outlet:call:{outlet_id}` are the parameterized categories — they restrict invocation to a specific outlet. `outlet:query:*` grants invocation of all registered Query outlets; `outlet:call:*` grants invocation of all registered Action outlets. A ceiling containing `outlet:query:*` implicitly includes all `outlet:query:{outlet_id}` capabilities; likewise for `outlet:call:*`. The two stems are independent: `outlet:query:*` does NOT grant any `outlet:call:*` capability (§5.4.2 classification, §6.2.0.3 amplification rule).

**Category validation.** At context creation, the SDK validates that every entry in the ceiling array is a recognized category string (exact match, case-sensitive). Unrecognized categories cause creation to fail with `InvalidCeilingCategory` error. This prevents forward-compatibility issues where an old SDK creates a context with categories it cannot enforce.

### 5.3.2 Governed Ceiling Change Notification Protocol

When a context uses the `governed` ceiling policy and a ceiling change is approved through governance:

1. **Proposal logged.** The `CeilingChangeProposed` event is recorded in the event log, containing the proposed new ceiling, the proposer's DID, and the governance justification.
2. **Notification period.** A mandatory notification period of 72 hours begins. During this period, the existing ceiling remains in effect. All current members receive a `CeilingChangeNotification` message (MLS application message in encrypted contexts, broadcast message in broadcast contexts) containing the proposed changes.
3. **Member response window.** During the notification period, members MAY leave the context if they disagree with the proposed changes. Members who leave during the notification period are recorded as `DepartedDuringCeilingChange` in the event log — this is informational, not punitive.
4. **Activation.** After the notification period expires, the new ceiling takes effect. A `CeilingChanged` event is recorded with the old ceiling hash, new ceiling, and the governance proposal ID.
5. **Retroactive UCAN validation.** After ceiling change activation, UCANs that reference capabilities no longer in the ceiling are automatically invalidated. The SDK MUST re-validate all cached UCANs against the new ceiling on the next action attempt.

## 5.4 Outlets

Contexts provide **outlets**: stateless functions that agents invoke. Outlets have no identity, no agency, no ability to initiate. They take input and return output. They are scoped to their context and cannot span contexts.

Outlets are the protocol's answer to "what about bots?" — anything that would have been a bot in a traditional system is an outlet in SCP. The critical difference: outlets cannot act, only respond. All agency flows through accountable agents.

**Terminology rationale.** The protocol uses "outlet" where ecosystems such as MCP and function-calling LLMs use "tool". The two words describe the same wire shape (stateless input→output functions gated by schema and capability) but carry different connotations. "Tool" is agent-centric — an instrument an agent wields. "Outlet" is context-centric — a socket the context exposes, which the context governs. SCP's security boundary is the context, not the agent, so the context-centric word is the one that matches the protocol's invariants. The rename is a hard break: there are no deprecation aliases, no migration period. External interop surfaces that use the MCP vocabulary (§8.5) translate lexically at the boundary in `scp-mcp`; inside SCP everything is an outlet.

Outlet registrations include:

- **Kind.** `OutletKind::Query` (read-only, idempotent, cacheable) or `OutletKind::Action` (may mutate, never cached). See §5.4.2. The default is `Action` — fail-safe.
- **Schema.** Input and output types (MCP-compatible JSON Schema — see §8.5). Machine-readable, self-documenting.
- **Implementation hash.** Content-addressable reference to the outlet's implementation. Any change to the implementation produces a new hash.
- **Test vectors.** Known input-output pairs that define correct behavior. Any agent can call the outlet with test inputs and verify outputs match. This enables continuous integrity verification (§7.3.3).
- **Operator DID.** The identity accountable for the outlet. Outlet misbehavior traces to this DID.
- **Cost metadata (optional).** Per-invocation cost declared by the outlet via an `OutletCost` struct (§5.4.1), additive with context-level costs (§19.3). An outlet calling an external API can pass through its cost. Outlet costs carry their own payee DID, which may differ from the context payee. Outlets without cost metadata are free. Query outlets MUST declare either no cost or a zero-amount cost (§5.4.2 structural floor).

Outlet mutations (implementation hash change, schema modification, test vector update, kind change) are recorded in the context's verifiable event log (§7.3.1). Silent outlet modification is not possible — any change is visible to all context members.

### 5.4.1 Outlet Registration Wire Format

Outlet registrations are serialized as MessagePack (§17.5) and stored in the context's outlet registry. The canonical structure:

```
OutletRegistration {
  outlet_id:        String,          // Unique within the context. Format: [a-z0-9_-], max 128 chars.
  kind:             OutletKind,      // Query or Action. See §5.4.2.
  name:             String,          // Human-readable name. Max 256 UTF-8 bytes.
  description:      String,          // Outlet description. Max 4096 UTF-8 bytes.
  operator_did:     DID,             // The identity accountable for this outlet.
  schema: {
    input:          JSONSchema,      // MCP-compatible JSON Schema for input. Max 64 KiB serialized.
    output:         JSONSchema,      // MCP-compatible JSON Schema for output. Max 64 KiB serialized.
                                     // MAY carry an `x-scp-query-ttl-secs` integer extension for
                                     // Query outlets (§5.4.2 cache TTL).
    aggregate_schema: Option<JSONSchema>, // Schema for the final aggregate value produced by a
                                     // streamed invocation (§5.4.5). Max 64 KiB serialized.
                                     // Absent = aggregate defaults to the final Data chunk.
  },
  implementation_hash: [u8; 32],    // SHA-256 of the outlet's implementation artifact (see below).
  test_vectors:     Vec<TestVector>, // Known input-output pairs. Min 0, max 100.
  cost:             Option<OutletCost>, // Per-invocation cost (§19.3). Query outlets: amount == 0.
  message_catalog:  Vec<MessageTemplate>, // §5.4.4 wire-time message catalog. ≤ 256 entries,
                                     // each template ≤ 1 KiB UTF-8. Covered by the V2 signature
                                     // preimage via `catalog_hash` (below).
  registered_at:    u64,             // Unix timestamp (seconds) of registration. See also the
                                     // event-log append time used for catalog-rotation dwell
                                     // enforcement (§5.4.4 Catalog-rotation discipline —
                                     // `registered_at` is operator-declared and therefore cannot
                                     // be trusted for dwell-time comparisons).
  signature:        Ed25519Signature, // Operator DID signs all fields except signature.
}

OutletKind {
  Query,   // Read-only, idempotent, cacheable. ReadOnlyInvocation guard applies (§5.4.2).
  Action,  // May mutate context state. Never cached.
}

TestVector {
  input:            Value,           // MessagePack value matching the input schema.
  expected_output:  Value,           // MessagePack value. Verification uses structural comparison,
                                     // not byte equality (§7.3.3).
  description:      String,          // Human-readable description of what this tests. Max 4096 UTF-8 bytes.
}

MessageTemplate {
  key:              String,          // Catalog key. Regex `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.
                                     // Unique within a catalog.
  template:         String,          // Pure UTF-8 string. NO interpolation slots. Max 1024 bytes.
}

OutletCost {
  amount:           Amount,          // Cost per invocation in smallest currency unit.
  currency:         CurrencyCode,    // ISO 4217 or protocol-defined.
  payee:            DID,             // Who receives payment. May differ from operator_did.
  cost_formula:     Option<String>,  // Optional pricing formula identifier for dynamic pricing (§19.4).
}
```

**Implementation hash target.** The `implementation_hash` is `SHA-256(canonical_artifact)` where `canonical_artifact` depends on the outlet type:

| Outlet type | Hash target | Description |
|-----------|-------------|-------------|
| Statically deployed (WASM, container) | SHA-256 of the binary artifact | The compiled WASM module or container image digest. Deterministic builds ensure the hash is reproducible. |
| Source-available | SHA-256 of the source archive | A tar.gz of the source tree, files sorted lexicographically, normalized line endings (LF). |
| Remote service (API-backed) | SHA-256 of the OpenAPI/JSON Schema spec | The canonical JSON serialization (RFC 8785) of the outlet's API specification. |
| LLM-backed (non-deterministic) | SHA-256 of the system prompt + model identifier | `SHA-256(model_id || ":" || system_prompt_utf8)`. Changes to the model or system prompt change the hash. |

The hash target type is NOT stored in the registration — the operator chooses what constitutes their implementation artifact. The hash provides a change-detection mechanism, not a verification mechanism. Verifiers detect changes (hash differs from registration); they do not verify what the hash covers.

**Signature scope.** The operator signs

```
SHA-256(
  "SCP-OUTLET-REGISTRATION-V2:"
  || BE32(len(outlet_id)) || outlet_id
  || kind_byte
  || BE32(len(name)) || name
  || description_hash
  || BE32(len(operator_did)) || operator_did
  || schema_hash
  || implementation_hash
  || test_vectors_hash
  || cost_hash
  || catalog_hash
  || registered_at_be
)
```

where:

- `kind_byte` is `0x00` for Query and `0x01` for Action (fixed 1-byte width).
- `BE32(n)` is `n` encoded as a 4-byte big-endian unsigned integer; this length prefix precedes every variable-length field (`outlet_id`, `name`, `operator_did`) so that concatenation is unambiguous and two registrations with different field splits can never produce the same preimage.
- `description_hash = SHA-256(description_utf8_bytes)` (32 bytes, fixed width). The `description` field is up to 4 KiB of operator-authored prose displayed to prospective invokers; like `message_catalog` it is operator-controlled text that sits outside the schema/implementation fingerprint, so it is equally a covert-channel surface if unbound. Committing `description_hash` into the V2 preimage binds the prose to the registration signature — a silent operator edit to `description` produces a new `implementation_hash`-independent registration event that members can diff.
- `schema_hash = SHA-256(MessagePack(schema))` (32 bytes, fixed width).
- `implementation_hash` is 32 bytes, fixed width.
- `test_vectors_hash = SHA-256(MessagePack(test_vectors))` (32 bytes).
- `cost_hash = SHA-256(MessagePack(cost))` (32 bytes), or `SHA-256(0x00)` (32 bytes) if absent. The sentinel preserves fixed width.
- `catalog_hash = SHA-256(MessagePack(message_catalog))` (32 bytes, fixed width). `message_catalog` is the ordered `Vec<MessageTemplate>` defined above; MessagePack serialization of an empty vector produces a 1-byte value (`0x90`) so `catalog_hash` is always well-defined. Committing the catalog into the V2 preimage is load-bearing for the §5.4.4 `OutletError.message` HMAC rule: without this binding, an operator could silently rotate catalog entries out-of-band and receivers would have no cryptographic proof of the catalog state that corresponds to any given signed registration event. The catalog is NOT covered by `schema_hash` — the schema preimage hashes only `input`, `output`, and `aggregate_schema` (per the `schema` field body), so a separate `catalog_hash` is required to bring the catalog under the signature.
- `registered_at_be` is `registered_at` encoded as a 8-byte big-endian unsigned integer.

The `V2` suffix, the `kind_byte` inclusion, the mandatory length prefixes on every variable-length field, and the explicit `description_hash` + `catalog_hash` terms together constitute the break from the pre-rename domain; pre-migration signatures are not honored. The length-prefix requirement closes the "split-shift" preimage-collision class that the unprefixed pre-rename concatenation admitted (where a suffix of `outlet_id` could be reinterpreted as a prefix of `name`). The explicit `description_hash` and `catalog_hash` close the operator-authored-prose covert-channel surface — every string field the operator controls at registration is covered by the registration signature.

### 5.4.2 Outlet Classification (Query vs Action)

Outlets declare their semantic class at registration time. Classification is structural, not advisory — the runtime enforces it.

**`OutletKind::Query`** — read-only, idempotent, cacheable in principle.

- **Structural floor at registration.** `cost == None || cost.amount == 0`. A Query outlet MUST NOT declare a positive per-invocation cost, and `cost.cost_formula` MUST be absent (a dynamic pricing formula on an idempotent read is not coherent). Declaring a positive cost or a pricing formula at registration is a validation failure (`OutletErrorClass::Protocol::QueryCostViolation`). Registrations that fail this check are rejected before they reach the event log.
- **ReadOnlyInvocation guard at invocation.** The runtime invokes Query outlets through a `ReadOnlyInvocation` handle that denies writes to context state (messages, roles, registry, event log, governance, economic ledgers). Any attempt by an executor to mutate through this handle returns `OutletErrorClass::Protocol::QueryViolation`.
- **Cacheability.** Query outlets are semantically cacheable (idempotent, invoker-independent result for fixed `(outlet_id, input, implementation_hash)`). A protocol-level shared cache is **deferred** (§5.4.3, discussion [#1698](https://github.com/limn-works/scp/discussions/1698)); every Query invocation currently executes live. The semantic property is stable — when the cache ships, it will not change what Query outlets are, only how the runtime exploits their properties.
- **Query-with-declared-cost is forbidden.** An outlet registered with cost amount `> 0` MUST be `Action`. Operators who want a paid read-only interface (e.g., a metered data lookup) declare it as `Action` and rely on the application layer to advertise semantics. The protocol contract is: a Query invocation is never billed. This invariant must hold regardless of whether a cache is present, because a future cache must be free to serve any Query to any member without inventing an economic event that did not exist at registration.
- **UCAN stem.** `outlet_query:{outlet_id}` or `outlet_query:*` (see §5.4.2.1 for parser semantics).
- **Chain depth (§6.2).** Query cross-context calls use the full `ContextParams::max_chain_depth` budget (default 8, range [1, 255]).
- **Rate tiers (§6.2.0.2).** Query per-interface default 600/min, per-caller default 100/min.

**`OutletKind::Action`** — may mutate, never cached.

- No structural cost floor; Action outlets may declare any cost.
- No ReadOnlyInvocation guard; Action executors may mutate context state through SDK-provided handles subject to role and capability checks.
- Never cached. Each invocation runs fresh.
- **UCAN stem.** `outlet_call:{outlet_id}` or `outlet_call:*` (see §5.4.2.1 for parser semantics).
- **Chain depth.** Action cross-context calls use `max(1, max_chain_depth / 2)` as their budget. Default 4 when `max_chain_depth` is default 8.
- **Rate tiers.** Action per-interface default 60/min, per-caller default 10/min (identical to the pre-classification baseline).

**Default.** `OutletKind::Action` is the default when `kind` is absent in an otherwise-valid registration (fail-safe). SDKs SHOULD surface `kind` as a required field in application APIs even though the wire format tolerates absence.

**Chain amplification rule (§6.2).** A Query outlet invocation MUST NOT transitively invoke any Action outlet through cross-context hops. The reverse is permitted — an Action invocation MAY transitively invoke Query outlets. The runtime enforces this at the cross-context consent gate (§6.2.0.1): on every hop, the runtime checks `hop.kind` against the originating request's `kind` and rejects Query→Action amplification with `OutletErrorClass::Authorization::AmplificationViolation`. This prevents a "free" read from being laundered into a paid write.

**Misdeclaration signal.** Any invocation that trips `QueryViolation` at runtime (an executor attempted a write inside a ReadOnlyInvocation) is recorded as an operator-attributable signal: the `OutletVerified` event for that outlet carries `integrity_ok: false` with reason `query_misdeclaration`, and participation records (§7.3.2) attribute the failure to the outlet's `operator_did`. No cache purge is specified (§5.4.3 is deferred).

#### 5.4.2.1 UCAN Capability Stem Parser

The two stems `outlet_query:` and `outlet_call:` are parsed with a fixed two-step algorithm:

1. **Literal prefix match.** The parser accepts only the literal byte sequences `outlet_query:` or `outlet_call:` (case-sensitive, UTF-8). Any other prefix — including abbreviations, trailing-colon variations, or concatenations such as `outlet_query:call:foo` — is a `Capability::parse` failure and MUST NOT be admitted as either stem. The colon is part of the stem, not a separator.
2. **Opaque suffix with outlet_id validation.** Everything after the prefix is the suffix. The suffix is either `*` (wildcard, matching `Capability::OutletQueryAll` / `OutletCallAll`) or a single outlet_id matching the regex `^[a-z0-9_-]{1,128}$`. No further `:` characters appear in a valid suffix; a colon in the suffix fails parsing (this blocks the `outlet_query:call:foo` parser-differential where a naive split-on-colon implementation would accept it).

Bridge and SDK parsers MUST apply this algorithm identically. A conformance test fixture (`tests/conformance/vectors/outlet_capability_parse.json`) enumerates positive and negative parse cases; every bridge must accept/reject each fixture identically.

The underscore in the wire form is deliberate: UCAN resource strings historically use `-` or `_` to disambiguate prefix from suffix, and `outlet:query:` (two colons) would require three-way parsing that invites prefix-vs-suffix ambiguity. The SDK-facing display form `outlet:query:{id}` is a pretty-print alias; it round-trips through `Capability::new` and `Capability::to_string` but is not the wire form.

### 5.4.3 Query Result Cache (Deferred)

A shared operator-signed relay-hosted Query result cache was drafted for this section during the outlet redesign but pulled from the initial scope before merge. Concrete design questions blocked it — notably: relay-side authentication and authorization boundaries for cache reads (the cache must be membership-gated but relays are not membership-aware); the interaction with per-member pseudonym routing (§9.10.4), which prevents the relay from grouping hits on a single routing ID without leaking subscribership; and the billing semantics of a paid Query operator serving an unbounded cached audience. None of those are dead-on-arrival, but none are ready to commit to either.

The deferral is tracked in GitHub discussion **[#1698](https://github.com/limn-works/scp/discussions/1698)**. Downstream sections do NOT assume a cache: §5.4.2 marks Query as "cacheable" as a semantic property of the kind, not as a claim that a cache exists; §5.4.5 does not rely on cache-hit paths; §5.14.10 does not allocate an `OutletQueried` event. When the cache ships, it will occupy this section number (§5.4.3) and be added via a new spec revision and ADR. Until then, every Query invocation executes live and records an `OutletInvokedEvent` per §5.4.5.

Implementations MUST NOT silently add a cache layer: a cache-like optimization that is not specified here is a protocol divergence, not an implementation detail, because it changes what `OutletInvokedEvent` records and what the operator signs for. Any local memoization must be fully contained within a single invocation (e.g., a handler's own in-memory cache during its lifetime) and MUST NOT persist state across invocations.

### 5.4.4 Outlet Error Taxonomy

Outlet invocations return a structured error envelope. The envelope is MessagePack-serialized with numeric field tags for forward compatibility.

```
OutletError {
  code:          String,          // tag 1; format "SCP-TOOL-{6100..6199}" — shares the
                                  // SCP-TOOL- prefix registered in sdk-common.md; outlets
                                  // carve out the 6100-6199 sub-block. Bridge linters
                                  // require the prefix and the sub-block.
  slug:          String,          // tag 2; dot-separated class-prefixed form,
                                  // regex `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.
                                  // The class-prefix segment (before the first `.`) MUST
                                  // match the lowercased OutletErrorClass variant name;
                                  // subsequent segments are finer distinctions (e.g.,
                                  // `authorization.expired`, `authorization.revoked`,
                                  // `authorization.attenuation-violation`). Multiple slugs
                                  // may share the same code. Slugs are class-scoped
                                  // identifiers; never surface as covert channels.
  class:         OutletErrorClass,// tag 3; one of eight root classes (below)
  message:       String,          // tag 4; human-readable, non-localized; max 1 KiB UTF-8.
                                  // See "Message content constraints" below.
  retry:         RetryPolicy,     // tag 5; see below
  detail:        Option<Value>,   // tag 6; typed per-class schema (below). Free-form
                                  // `detail` is forbidden — a cooperating producer cannot
                                  // use `detail` as a covert channel.
  source_chain:  Vec<ContextHop>, // tag 8; ordered list of cross-context hops the
                                  // error traversed (§6.2). See pseudonymization below.
}
```

Tags `7`, `9`, and `10` are **reserved for forward-compatible evolution** and are not used in this version of the envelope. They were drafted (`related_code`, `i18n_key`, `trace_id`) and dropped before merge — the cross-reference use case is served by `source_chain.wrapped_code`; localization is an SDK-layer concern that does not belong on the wire; and telemetry `trace_id` is not a protocol-level field (see discussion [#1698](https://github.com/limn-works/scp/discussions/1698)). Tag `11` carries the `pad_nonce: [u8; 16]` field introduced below for trail-length padding verification — emitted unconditionally (no Option wrapper) on every envelope to eliminate the presence-vs-absence visibility oracle. Tag `12` carries the `registration_event_id: [u8; 32]` field introduced below for per-registration message-key lookup across re-registration windows — emitted unconditionally. Any future extension MUST use tags `13+` and MUST round-trip through the `_unknown_fields` forward-compat slot so old SDKs that see the new tag preserve it without interpretation.

```
OutletErrorClass {
  Protocol,      // registration/validation/classification violations
  Authorization, // UCAN, caveat, role, capability, amplification
  Input,         // schema, size, type, enum, range
  Execution,     // timeout, panic, resource-exhaustion, non-determinism
  Output,        // schema violation, size, non-serializable, redaction
  Economic,      // budget, insufficient funds, adapter failure, pricing (§19)
  Transport,     // relay unavailable, cross-context bridge failure
  Governance,    // deregistered, suspended, revoked, ceiling exceeded
}

RetryPolicy {
  Never,                                        // permanent; do not retry
  Immediate,                                    // safe to retry immediately (idempotent)
  After(Duration),                              // retry after fixed delay
  WithBackoff { min: Duration, max: Duration }, // exponential within bounds
}

ContextHop {
  context_id:   ContextId,    // pseudonymized; see "source_chain pseudonymization" below
  hop_index:    u16,          // for real hops: 0 = origin, increments per cross-context
                              // boundary. For pad entries: equals the zero-based slot index
                              // within the padded trail (0..max_padded_trail_depth), so pad
                              // entries are byte-indistinguishable from real-hop slots at
                              // the same slot index. See "Trail-length padding" below.
  wrapped_code: String,       // code as it was before wrapping at this hop
}
```

`OutletError` carries two additional fields outside the `ContextHop` itself: `pad_nonce` (used to derive trail-padding entries, and — in the un-padded case — emitted unconditionally to defeat the presence-vs-absence visibility oracle) and `registration_event_id` (used by the receiver to look up the per-outlet HMAC key that was in force for the outlet registration under which this envelope was signed, so in-flight envelopes from a prior registration do not DoS themselves at lookup time when the outlet is re-registered mid-flight):

```
OutletError {
  ...                                     // tags 1..8 as above
  pad_nonce:             [u8; 16],        // tag 11; ALWAYS present on every error envelope (no
                                          // Option wrapper). Fresh-per-envelope CSPRNG-sampled
                                          // nonce that keys the HMAC used to derive pad-slot
                                          // `context_id` values when source_chain is padded.
                                          // For un-padded envelopes the field is emitted but
                                          // unused on decode (the receiver's `k == max_padded_trail_depth`
                                          // check determines whether padding is present; the
                                          // nonce is ignored when k matches the true length).
                                          // Emitting unconditionally closes the visibility
                                          // oracle where "pad_nonce absent" leaked that the
                                          // caller had full visibility into every hop.
  registration_event_id: [u8; 32],        // tag 12; ALWAYS present. The event-log id of the
                                          // OutletRegistration event under which the emitting
                                          // outlet's outlet_message_key was derived and pinned.
                                          // The receiver looks up the matching outlet_message_key
                                          // in its per-outlet LRU (`registration_event_id →
                                          // outlet_message_key`, capacity N=4 per outlet, oldest-
                                          // first eviction) and HMAC-verifies the `message` field
                                          // under that key. Closes the in-flight-error DoS surface
                                          // at re-registration: an envelope signed under the prior
                                          // outlet_message_key still resolves at the receiver for
                                          // as long as the prior registration fits within the LRU
                                          // window, rather than being silently rejected as
                                          // `UnregisteredMessageKey`. The field is always emitted
                                          // (every OutletError references the registration it was
                                          // emitted under), so there is no presence-oracle.
}
```

**Code range.** `6100..=6199` within the `SCP-TOOL-` prefix, sub-allocated as follows. Distinct runtime conditions within a code share one code and differ by `slug` — the code set is intentionally compact (one to two codes per class, ~15 codes total) so the full taxonomy is memorable and the wire form is not a sprawling enumeration.

- `6100-6109` — Protocol class (query/kind/amplification violations; schema/cache violations; catalog-rotation dwell-time; stream-lifecycle violations; session uniqueness)
- `6110-6119` — Authorization class (UCAN, caveat, amplification, missing outlet, adapter denial, mid-stream revocation, credit-stream mismatch, IKM signature invalid, salt-rotation unjustified, mask-width violation, mixed-stem/unspecified/stem-mismatch origin_kind)
- `6120-6129` — Input class (schema, size, non-serializable)
- `6130-6139` — Execution class (handler panic, timeout, credit exhaustion, stream gap, cancel-ack-timeout)
- `6140-6149` — Output class (schema, size, non-serializable)
- `6150-6159` — Economic class (funds, adapter, pricing, budget, interface-spam quadratic fee)
- `6160-6169` — Transport class (relay, cross-context bridge, rate limit, concurrent-streams-per-invoker / per-origin-invoker / per-outlet)
- `6170-6179` — Governance class (deregistered, suspended, ceiling, consequence active)
- `6180-6199` — reserved

**Slug allocations added in round 5.** The following slugs are registered within the existing class ranges (no new codes — slugs differentiate conditions under a shared code):

| Slug | Code | Class | Source |
|------|------|-------|--------|
| `protocol.catalog-rotation-too-frequent` | `SCP-TOOL-6100` | Protocol | §5.4.4 Catalog-rotation discipline |
| `protocol.stream-already-open` | `SCP-TOOL-6100` | Protocol | §6.2.1.1(b) |
| `protocol.session-id-conflict` | `SCP-TOOL-6101` | Protocol | §6.2.1.1(a) UUIDv7 uniqueness |
| `protocol.interface-spam-cost` | `SCP-TOOL-6150` | Economic | §6.2.0.1 quadratic fee |
| `authorization.credit-stream-mismatch` | `SCP-TOOL-6110` | Authorization | §5.4.5 credit-grant stream identity |
| `authorization.revoked-mid-stream` | `SCP-TOOL-6110` | Authorization | §5.4.5 revocation re-check |
| `authorization.ikm-signature-invalid` | `SCP-TOOL-6110` | Authorization | §6.2.0.1 committed-IKM signature |
| `authorization.salt-rotation-unjustified` | `SCP-TOOL-6115` | Authorization | §6.2.0.1 admin-removal salt-rotation trigger binding — rejects an `InterfaceSaltRotated` event whose `removal_event_id` does not reference a prior, valid, unreplayed admin-removal event within the required epoch window |
| `attenuation.origin-kind-mixed-stem-root` | `SCP-TOOL-6114` | Authorization (attenuation sub-class) | §7.3.8 root-mint consistency |
| `attenuation.origin-kind-stem-mismatch` | `SCP-TOOL-6114` | Authorization | §7.3.8 root-mint consistency |
| `attenuation.origin-kind-unspecified` | `SCP-TOOL-6114` | Authorization | §7.3.8 narrow-time explicit-materialization |
| `attenuation.mask-width-violation` | `SCP-TOOL-6114` | Authorization | §7.3.8 mask-width newtype invariant |
| `transport.concurrent-streams-per-invoker` | `SCP-TOOL-6160` | Transport | §5.4.5 per-invoker cap |
| `transport.concurrent-streams-per-origin-invoker` | `SCP-TOOL-6160` | Transport | §5.4.5 + §6.2.0.5 per-origin cap |
| `transport.concurrent-streams-per-outlet` | `SCP-TOOL-6160` | Transport | §5.4.5 per-outlet cap |
| `execution.cancel-ack-timeout` | `SCP-TOOL-6135` | Execution | §5.4.5 cancel-ack timer (round 4) |

**Slug allocations added in round 8.** The following slugs are registered within the existing class ranges (no new codes — slugs differentiate conditions under a shared code). All three are sound-by-addition refinements: a new slug under an existing code band, paired with a new closed-enum `TerminateReason` variant and a per-instance node-level pump ceiling. No ratchet movement.

| Slug | Code | Class | Source |
|------|------|-------|--------|
| `execution.stream-cap-exhausted` | `SCP-TOOL-6131` | Execution | §5.4.5 node-level concurrent-pump ceiling (round 8) |
| `protocol.context-closed-mid-stream` | `SCP-TOOL-6101` | Protocol | §5.4.5 context evict/leave race during active stream (round 8) |
| `protocol.stream-already-closed` | `SCP-TOOL-6101` | Protocol | §5.4.5 control-plane method (`grant_credit`/`cancel`/`terminate`) invoked after the stream reached a terminal chunk (round 8) |

`protocol.stream-already-closed` shares `SCP-TOOL-6101` with `protocol.unknown-session` and `protocol.context-closed-mid-stream` — all three are Protocol-class session-lifecycle conditions. A control-plane call against an already-terminal stream is a session-lifecycle violation, not an authorization denial, so it carries the Protocol-session band and MUST NOT collapse onto the Authorization-class `SCP-TOOL-6110`. The SDK lifecycle-guard surface (`StreamAlreadyClosed`) maps to this slug.

`execution.stream-cap-exhausted` shares `SCP-TOOL-6131` with `execution.credit-exhausted` and `execution.stream-gap` — all three are Execution-class resource-exhaustion conditions. It is emitted at `OutletStreamOpen` acceptance when the node-level concurrent-pump ceiling (below) is already saturated; the open is hard-rejected and no stream-table entry, escrow, or admission counter is mutated.

`protocol.context-closed-mid-stream` shares `SCP-TOOL-6101` with the other Protocol-session conditions. It carries the Protocol-class `CODE_PROTOCOL_SESSION` band rather than the Authorization-class `authorization.revoked-mid-stream` (`SCP-TOOL-6110`) deliberately — see §5.4.5 "Context teardown vs. revocation" below.

The `SCP-TOOL-` prefix is preserved (not renamed to `SCP-OUTLET-`) because the CI enforcement script `scripts/check-error-codes.sh` indexes prefixes in a closed set — adding a new top-level prefix requires coordinated changes across every language SDK's error surface. Sub-block allocation within the existing prefix is the forward-compatible path.

**Cross-context wrapping.** A cross-context error is not translated — the original `code` is preserved and the wrapping hop appends to `source_chain` with its own `wrapped_code`. The outermost caller sees the innermost reason and the trail of boundaries it crossed. This is the opposite of HTTP-style gateway remapping, which loses causal information.

**Query oracle collapse.** Authorization errors that would reveal whether a specific `outlet_id` exists MUST be collapsed to a single indistinguishable outcome when the caller does not hold a capability that would let them disambiguate. Concretely: a caller who presents a UCAN matching neither `outlet_query:{id}` nor `outlet_call:{id}` receives `SCP-TOOL-6110` with slug `authorization.denied` regardless of whether the outlet is registered, deregistered, or has never existed. The specific sub-errors (`outlet.not-found`, `outlet.kind-mismatch`) are observable only by callers who hold at least one stem on the outlet. Without this collapse, a caller who holds no capability can enumerate the outlet registry by probing error codes — a practical oracle against private outlets.

The collapse extends to cross-context attenuation and amplification signals carrying the same disambiguating power:

- `OutletErrorClass::Authorization::AttenuationViolation` (slug `authorization.attenuation-violation`) and `OutletErrorClass::Authorization::AmplificationViolation` (slug `authorization.amplification-violation`) collapse to `SCP-TOOL-6110` slug `authorization.denied` when the caller does not hold **both** stems required to observe the distinction. A caller who holds neither `outlet_query:{id}` nor `outlet_call:{id}` on the hop target cannot distinguish "attenuation failed" (the token was narrowed incorrectly) from "amplification forbidden" (Query → Action is rejected) from "outlet does not exist at all" — all three produce `authorization.denied`. A caller who holds only one stem (e.g., `outlet_query:{id}` but not `outlet_call:{id}`) ALSO cannot distinguish amplification from a kind-specific denial — `AmplificationViolation` specifically collapses to `authorization.denied` for any caller missing `outlet_call:{id}`, because the amplification error would otherwise leak the existence of an Action outlet under that id. Only a caller holding BOTH `outlet_query:{id}` AND `outlet_call:{id}` — i.e., a caller with full visibility into both kinds on the target — sees the disambiguated slug.
- The same collapse applies per-hop to `ContextHop.wrapped_code` entries within `source_chain`. At every hop the caller is not a member of, `wrapped_code` is collapsed to `SCP-TOOL-6110` before emission, and the accompanying slug is rewritten to `authorization.denied`. This prevents the caller from reconstructing the disambiguated error trail of hops they cannot observe — the `source_chain` still records the structural fact that a hop occurred, but not the fine-grained error type at that hop. Callers with membership (or a matching stem on the hop target) see the original `wrapped_code` and slug unchanged.

**Trail-length padding.** The *length* of `source_chain` is itself a side-channel: a caller who observes that their error trail has 3 hops can infer that the hostile hop chain crossed exactly 3 boundaries, even when every individual hop is collapsed. To close this, `source_chain` is length-padded to a fixed `max_padded_trail_depth` with indistinguishable pad entries whenever any hop is opaque to the caller.

The padded depth is `max_padded_trail_depth = min(ContextParams::max_chain_depth, MAX_TRAIL_PAD_DEPTH)` where `MAX_TRAIL_PAD_DEPTH = 16` is a protocol constant (registered in §9.18.B). Capping the padded depth at 16 bounds envelope size even when an operator configures `max_chain_depth = 255`; without the cap, the padded `source_chain` would consume ≥ 8 KiB per error envelope. Emitter and verifier use the emitter-context's `max_chain_depth` parameter when computing the cap, so a single error envelope commits to one padded length that all collapse-visible receivers agree on.

**Emission rule.** If the true chain has `k` real hops and any of those hops is opaque to the caller (caller is not a member of that hop's context and does not hold a matching stem on that hop's target outlet), the emitted `source_chain` has exactly `max_padded_trail_depth` entries:

- Entries at slot indices `0 .. k-1` are the real hops (with per-hop collapse applied as above) — each real-hop entry's `hop_index` carries the slot index it occupies in the padded trail (which equals its real hop index).
- Entries at slot indices `k .. max_padded_trail_depth - 1` are pad entries.

Every pad entry (real or pad) carries `hop_index = slot_index`, so a padded trail contains exactly `max_padded_trail_depth` entries with `hop_index` values `[0, 1, ..., max_padded_trail_depth - 1]` regardless of `k`. This eliminates the `hop_index = k + pad_offset` leak in the earlier draft, where the pad entry's `hop_index` literally encoded the real chain length `k`.

**Pad pseudonym construction.** The error envelope carries a fresh `pad_nonce: [u8; 16]` field (tag 11), sampled from a CSPRNG at envelope construction time. Every pad entry derives its `context_id` and `wrapped_code` from this per-envelope nonce:

```
pad_entry.context_id =
  HMAC-SHA-256(
    pad_nonce,
    "SCP-OUTLET-HOP-PAD-V1:" || slot_index_be   // slot_index as 2-byte BE u16
  )[..32]

pad_entry.hop_index    = slot_index              // matches real-hop encoding
pad_entry.wrapped_code = "SCP-TOOL-6110"         // authorization.denied
```

The `SCP-OUTLET-HOP-PAD-V1:` domain separator is registered in §9.18.2. Because `pad_nonce` is fresh per envelope, pad pseudonyms differ across every emission — two error envelopes from the same stream cannot be diffed byte-for-byte to identify which slots are real and which are pad. A receiver who wants to verify pad entries re-derives them locally from the transmitted `pad_nonce` and matches byte-equality at the claimed pad slots; real-hop entries never match the re-derived pad pseudonym at that slot (the real-hop `context_id` is an HMAC keyed by `hop_salt`, not `pad_nonce`, and the two keyings are independent per §9.5.1 domain-separation rules).

**Partial-visibility disclosure.** The pad + real-hop construction is honest about its scope: it hides `k` (the real chain length) from observers who cannot compute any involved `hop_salt`. A receiver who IS a member of some hop `i` holds the `hop_salt` for that hop and can therefore compute `HMAC(hop_salt, their_context_id)` and compare it against each slot's `context_id`. That member can identify exactly which slot corresponds to their hop — and, by the uniqueness of the HMAC output, can label that slot as "real"; they cannot identify other real slots (those use different hop-salt keys the observer does not hold). So a single-hop member observes a real-vs-pad distinction at their own hop only; they learn that slot `i` is real and its real `hop_index == i`, but they still do not learn whether any other slot is real or pad and therefore do not learn `k`. The pad continues to hide `k` from such an observer; it does NOT hide the existence of the member's own hop (which the member already knows). The pad fully hides `k` only from observers who hold no `hop_salt` — i.e., non-members of every hop. This is the design's target threat model (non-member chain-length inference), and the spec states the property honestly rather than claiming universal opacity. A cryptographic construction giving universal opacity would require re-HMACing every real-hop slot under `pad_nonce` too (producing `HMAC(pad_nonce, SCP-OUTLET-SLOT-V1 || slot_index || HMAC(hop_salt, raw_context_id))` on the wire), which was considered and rejected: the partial-visibility length oracle is a niche attack available only to someone who is already a hop member (and therefore already sees their hop structurally), and the extra re-HMACing imposes verifier and SDK complexity on every real-hop read without closing a practically-exploitable channel.

**Full-visibility path.** Callers with membership on every hop AND a matching stem on every hop target see the un-padded `source_chain` (length `k`). Every other caller sees the padded form (length `max_padded_trail_depth`). In both cases the `pad_nonce: [u8; 16]` field is emitted on EVERY `OutletError` envelope unconditionally — for the un-padded path the field is still present and is used only as a domain-separating constant (the receiver checks the slot count against `k` and ignores the nonce), for the padded path the field keys the pad-slot derivation. Emitting `pad_nonce` unconditionally eliminates the "absence of `pad_nonce` == full visibility" visibility-oracle: an on-wire observer cannot distinguish padded vs un-padded envelopes by presence-vs-absence of the field, because the field is always present. The 16-byte fixed cost per envelope is the price paid for the visibility oracle's removal.

This keeps trail length independent of the actual number of hops traversed, at the cost of `max_padded_trail_depth × entry_size + 16` bytes per error envelope — a bounded tradeoff against an otherwise-free oracle on chain depth.

**Per-class `detail` schemas.** `detail` is NOT free-form. Each class defines a typed schema; detail MUST match or be absent. This prevents operators from using `detail` as a covert channel.

| Class | `detail` schema | Example |
|-------|-----------------|---------|
| Protocol | `{ rule: string }` — the rule name that was violated | `{ rule: "query-cost-floor" }` |
| Authorization | `{ capability: string }` — the capability URI that was denied | `{ capability: "outlet_query:foo" }` |
| Input | `{ field_path: string, violation: string }` — JSON Pointer + violation tag | `{ field_path: "/items/0", violation: "type" }` |
| Execution | `{ elapsed_ms: u64 }` for timeouts; `{ panic_location_hash: [u8; 32] }` for panics (full `SHA-256("file:line")`; the operator keeps a local resolution table mapping hash → raw file:line — the full 32-byte digest prevents birthday-style collisions that a truncated 16-byte hash would admit when the operator's codebase has > 2^56 `(file, line)` pairs across lifetime); `{}` otherwise | `{ elapsed_ms: 30000 }` |
| Output | `{ field_path: string, violation: string }` same as Input | |
| Economic | `{ needed: Amount, currency: CurrencyCode }` for InsufficientFunds; `{ adapter_id: PaymentAdapterId }` for adapter errors | `{ needed: 100, currency: "USD" }` |
| Transport | `{ retry_after_secs: u32 }` for rate limits; `{ relay_url_kind: enum }` (`wss` \| `ws-loopback` \| `unknown`) for relay errors — never a raw URL | `{ retry_after_secs: 30 }` |
| Governance | `{ action: string }` — the governance action name | `{ action: "outlet-deregistered" }` |

Absent schemas: classes with `{}` detail have detail omitted entirely. An envelope that carries a non-empty `detail` whose shape does not match its class is a **wire-layer rejection** (SDK MUST reject during deserialization), not a runtime error. Schema violations are detected at the receiving SDK boundary so a misbehaving producer cannot smuggle arbitrary data through `detail`.

**Message content constraints.** The `message` field is human-readable prose intended for logs and operator tooling, not for end-user display. Producers MUST NOT include:

- User-identifying data (email addresses, DIDs of members other than the invoker's own, names, account IDs).
- Internal implementation strings (SQL fragments, stack traces, file paths above the outlet source root, private-network addresses, secret fragments).
- Raw input values (input echo in error messages is the fastest path to smuggling data out of a constrained context).

**Message structural rule — registered catalog, per-outlet-HMAC'd on wire.** `message` is structurally constrained in two composed stages:

1. **Registration-time catalog.** Every `OutletRegistration` carries a `message_catalog: Vec<MessageTemplate>` of at most 256 entries; each entry is `{ key: String, template: String }` where `template` is a pure string (no interpolation slots) bounded at 1 KiB UTF-8. Runtime substitution is explicitly forbidden so the on-wire catalog selection is a bounded discrete channel. Catalog contents are covered explicitly by the outlet registration signature via the `catalog_hash = SHA-256(MessagePack(message_catalog))` term of the `SCP-OUTLET-REGISTRATION-V2` preimage (§5.4.1) — a dedicated term, NOT via `schema_hash` (the `schema` preimage hashes only `input`, `output`, and `aggregate_schema`). Diffs to the catalog produce a new registration event and therefore a new signed preimage.
2. **Wire-time HMAC over catalog key, keyed per outlet.** The `message` field on the wire is NOT the catalog key in plaintext. At registration acceptance, each outlet derives and pins a 32-byte per-outlet message key from the hosting context's MLS exporter:

   ```
   outlet_message_key =
     MLS_EXPORTER(
       "scp-outlet-message-v1:" || BE32(len(outlet_id)) || outlet_id,
       b"",
       32,
     )  // exporter taken on the hosting context's MLS epoch at the moment the
        // OutletRegistration is accepted (i.e., committed by MLS at registration
        // time), NOT re-evaluated at each error emission. The key is stored in
        // the outlet's registration state alongside the accepted event.
   ```

   For every `OutletError`, the operator constructs:

   ```
   wire_message = HMAC-SHA-256(outlet_message_key, catalog_key_utf8)[..32]
   ```

   The wire field carries this 32-byte opaque HMAC output. Members of the hosting context, holding the pinned `outlet_message_key` derived at registration-acceptance time, reverse-lookup the HMAC against the outlet's registered catalog keys to obtain the catalog entry; non-members see only the 32-byte opaque value.

   Per-outlet-and-per-context keying defeats cross-context signaling AND closes the epoch-grace covert channel. An operator running the same outlet registration in contexts P and Q produces different HMAC outputs for the same `catalog_key`, because each context's MLS exporter produces a distinct key at accept time. An operator holding two concurrent memberships during an epoch-grace window in a single context (one using epoch E's exporter, one using epoch E+1's exporter) would — under the previous per-emission-epoch rule — have produced two distinct wire-byte sequences for the same `catalog_key`, encoding one bit of covert signal per emission straddling the grace boundary; pinning the key at registration acceptance eliminates this channel entirely. There is exactly one `outlet_message_key` per outlet registration; grace-window epoch transitions do NOT re-derive it and do NOT rotate it.

   `outlet_message_key` is pinned for the lifetime of the outlet registration (implementation_hash-locked). The key rotates ONLY when the outlet is re-registered (producing a new `registered_at`, a new `SCP-OUTLET-REGISTRATION-V2` signature, and — if MLS has advanced — a new derived key from the then-current exporter at the re-registration's acceptance epoch). A deregister-then-register sequence produces a fresh `outlet_message_key`; a silent catalog-only edit within the same outlet_id DOES trigger re-registration under the catalog-rotation discipline below, so any catalog change is paired with a fresh key.

   **Receiver lookup across re-registration windows — `registration_event_id` and the per-outlet LRU.** At the receiver, each outlet's registration state maintains a bounded LRU keyed by `registration_event_id: [u8; 32]` with at most `MESSAGE_KEY_LRU_CAPACITY = 4` entries (protocol invariant, registered in §9.18.A). Each entry maps an outlet-registration's event-log id to the `outlet_message_key` that was pinned at that registration's acceptance. On every `OutletRegistration` acceptance, the receiver inserts `(registration_event_id, outlet_message_key)` into the LRU, evicting the oldest entry if the capacity is exceeded. When a receiver processes an `OutletError` envelope, it uses the envelope's `registration_event_id` (tag 12) to look up the matching `outlet_message_key` in the LRU; if the lookup hits, the receiver HMAC-verifies the `message` field under the matched key; if the lookup misses (the cited registration has aged out of the LRU), the receiver rejects the envelope with `OutletErrorConstructionFailed::UnregisteredMessageKey`. The LRU thus keeps up to the four most recent registrations for each outlet resolvable concurrently, covering in-flight errors that were signed under a prior registration and are still traversing cross-context hops when a re-registration lands. Four is sufficient because outlet re-registration is a governance action subject to catalog-rotation dwell (≥ 24 h between catalog-modifying re-registrations under §5.4.4 dwell rule): an envelope that is in flight longer than 4 × 24 h = 96 h is already outside any reasonable propagation window.

   **Emitter rule for `registration_event_id`.** The emitting outlet always sets `OutletError.registration_event_id` equal to the event-log id of the registration whose `outlet_message_key` was used to compute `wire_message`. Because an emitting outlet always uses its currently-pinned key (and pins the key at registration acceptance), the cited `registration_event_id` is always the outlet's current registration id — not a prior one — on emission. The LRU resolution is therefore used only on cross-hop / cross-recipient propagation where a re-registration landed between emission and receipt.

   An error whose wire-time `message` does not match any catalog entry's HMAC under the LRU-looked-up `outlet_message_key` is rejected at the receiving SDK with `OutletErrorConstructionFailed::UnregisteredMessageKey`. An error whose `registration_event_id` does not hit the LRU at all — because the registration has aged out — is likewise rejected with `UnregisteredMessageKey`: the receiver has no cryptographic evidence that the cited registration ever existed in the expected form, and accepting a miss on the strength of the envelope alone would admit a covert-channel surface.

The catalog-plus-per-outlet-HMAC approach subsumes the earlier free-text constraint: a catalog template cannot contain input-derived bytes (the operator wrote the template at registration time, before the input existed); i18n-ready future extensions can carry per-locale variants without a wire break (the HMAC keys lookups, not content); cross-context covert signaling is structurally impossible — the wire bytes are an outlet-keyed MAC over a bounded input set of at most 256 catalog keys; and the epoch-grace wire-byte-divergence covert channel is closed because grace windows never touch the `outlet_message_key`.

**Catalog-rotation discipline.** `OutletRegistration.message_catalog` edits appear in the event log (via the outlet registration event the operator must emit) and are subject to a protocol-enforced minimum dwell time of 24 hours between successive catalog edits on the same outlet. Dwell-time enforcement uses the **event-log append time** of the prior registration (`event_log.append_time_for(prior_registration)`), NOT the operator-declared `registered_at` field. A registration update whose `message_catalog` differs from the prior registration's catalog AND whose own event-log append time is within 24 hours of the prior registration's event-log append time is rejected with `OutletErrorClass::Protocol::CatalogRotationTooFrequent` (slug `protocol.catalog-rotation-too-frequent`). Using the event-log append time (a protocol-enforced, verifiably-ordered clock — §7.3.1) rather than `registered_at` (an operator-declared integer the operator can set arbitrarily) denies the operator the ability to back-date a registration to bypass the dwell-time floor. The dwell-time bound is not configurable; it removes the cooperating operator's ability to use high-frequency catalog churn as a side-channel.

SDKs SHOULD additionally apply a lint pass to resolved catalog templates that redacts recognizable patterns (`/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/` for emails; `/did:(dht|web|key):[A-Za-z0-9._-]+/` for DIDs) before surfacing to developer-facing logs, replacing matches with `[redacted]`. Conformance fixtures include PII-redaction test cases, cross-context HMAC distinctness cases (the same `catalog_key` produces different wire bytes under two different contexts' exporters), and `CatalogRotationTooFrequent` rejection cases.

**`source_chain` pseudonymization.** A raw `context_id` in a cross-context error trail leaks membership — a caller who sees the actual context IDs of hops they are not a member of learns the existence and identity of those contexts. Each `ContextHop.context_id` MUST be pseudonymized for hops the receiving caller does not have membership in:

```
ContextHop.context_id_on_wire =
  HMAC-SHA-256(
    hop_salt,
    raw_context_id
  )
```

where `hop_salt` is a 32-byte per-context-pair salt established at outlet-interface acceptance (§6.2.0.1) between the two contexts on either side of the hop. The salt is visible to both contexts' members but not to outside observers. A caller who is a member of the target context sees the pseudonymized ID and can cross-reference locally; a caller who is not a member sees an opaque 32-byte value that reveals only the fact of a hop. The outermost caller's own hop (`hop_index == 0`) is the caller's own context and is NOT pseudonymized (the caller is always a member of their own context).

The salt-per-pair design means a single context's ID produces different pseudonyms in different interface relationships — so an observer who sees pseudonyms from multiple hops cannot correlate across interface relationships that the caller is not part of.

**Sealed SDK hierarchies.** Each SDK renders `OutletErrorClass` as a sealed type: Python subclass tree under `OutletError`, TypeScript tagged-union class with a runtime `instanceof` guard per concrete subclass, Swift `enum` with associated values, Kotlin sealed class with data-class children. The wire form is the source of truth; SDK types are generated from a shared fixture set round-tripped through all four FFI bridges. TypeScript conformance explicitly verifies prototype-chain preservation across the napi-rs FFI boundary (`err instanceof AuthorizationError` must hold after the error crosses the bridge).

**Rejected alternatives (for this section).** (1) Free-form `detail`: rejected because it is a covert-channel surface with no benefit over a typed schema. (2) `i18n_key` on the wire: rejected because localization is an SDK-layer concern; bundling translation keys on the wire couples protocol evolution to translation catalog churn. (3) `trace_id` on the wire: rejected because OpenTelemetry trace propagation is a transport-layer concern with its own conventions; duplicating it in the outlet envelope invites divergence. (4) A 35-entry code enumeration: rejected in favor of a ~15-code taxonomy that uses `slug` for fine-grained distinctions. Full enumeration would have created one code per distinguishable runtime condition and made the wire form unmemorable; the compact taxonomy keeps the code set within the 6100-6199 sub-block comfortably and moves variability into `slug`. (5) Input-echo 4-byte substring invariant: rejected because the context-keyed HMAC over registered-catalog keys (above) already makes arbitrary input bytes structurally impossible to encode into the wire `message`; the 4-byte window added no security margin on top of the catalog + HMAC rule and admitted false positives on legitimate short catalog entries that happened to share a 4-byte substring with canonicalized input. The catalog-plus-HMAC rule stands alone.

### 5.4.5 Progressive Output (Streaming)

Outlet invocations are streams by construction. A non-streaming invocation is the degenerate single-chunk case; there is no separate `OutletResponse` wire type.

**Wire types.**

```
OutletStreamOpen {
  request_id:             [u8; 16],      // per-stream UUIDv7; monotonic time-sortable
  outlet_id:              String,
  input:                  Value,          // MessagePack value matching input_schema
  invoker_did:            DID,
  ucan:                   Vec<u8>,        // UCAN JWT bytes; checked ONCE at open
  caveats_binding:        [u8; 32],       // SHA-256 over (ucan_cid, request_id, invoker_did,
                                          // estimated_chunk_count, caveats); see
                                          // "caveats_binding preimage" below
  chain_depth:            u8,              // inherited from opening call on cross-context hops;
                                          // matches §24.4 width [0, 255] and ADR-043
  credit_window:          u32,            // initial credit; see backpressure below
  estimated_chunk_count:  u32,            // invoker-declared upper bound on billable (Data)
                                          // chunks; used for escrow-at-open computation.
                                          // Coerced from caveats as
                                          //   caveats.max_calls
                                          //     .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
                                          //     .unwrap_or(u32::MAX)
                                          // when the invoker does not declare an explicit value.
                                          // MUST satisfy estimated_chunk_count <=
                                          //   min(credit_window, caveats.max_calls.unwrap_or(u32::MAX))
                                          // on Action outlets; otherwise the open is rejected
                                          // with OutletErrorClass::Input::EstimateExceedsBound.
                                          // For Query outlets and zero-cost Action outlets
                                          // the value is advisory (escrow = 0 regardless).
  session_id:             Option<String>, // optional stateful-session binding; when present the
                                          // open MUST reference a non-expired session owned by
                                          // this caller with a compatible origin_kind and the
                                          // session-pinned caveats_binding (§6.2.1.1).
  timeout_ms:             u32,             // absolute stream timeout; 0 = use context default
}

OutletStreamChunk {
  request_id:  [u8; 16],
  sequence:    u64,              // strictly monotonic per request_id, starting at 0
  payload:     ChunkPayload,
  sig:         Ed25519Signature, // operator's signature; preimage below
}

ChunkPayload {
  // Tagged union. The discriminator field is named `@type` (with a leading `@`) so that
  // under RFC 8785 JCS sort order it lexicographically precedes every lowercase-letter
  // key used by the variant bodies — ASCII `@` (0x40) sorts before `a`..`z` (0x61..0x7A).
  // Result: the canonical-hashed serialization of every variant has `"@type"` as its
  // first key, and the variant is unambiguously classified before any body field is read.
  // (The earlier draft used `"type"`, which under JCS sorts AFTER `aggregate`, `code`,
  // `execution_time_ms`, `message`, `note`, `pct`, `provenance`, and `terminal` — i.e.,
  // last in every variant — defeating the "classify first" property.)
  { "@type": "data",     "value": Value },                          // matches output_schema
  { "@type": "progress", "pct": u16, "note": Option<String> },      // pct in [0, 10000] bp
  { "@type": "end",      "aggregate": Value, "provenance": Provenance,
                         "execution_time_ms": u64 },                 // matches aggregate_schema
                                                                     // or defaults to last Data
  { "@type": "error",    "code": String, "message": String,
                         "terminal": bool },                         // terminal=true closes
}

OutletStreamCredit {
  request_id:    [u8; 16],
  grant:         u32,                     // additional chunks the executor may send
  monotonic_seq: u64,                     // per-(request_id) monotonic grant counter,
                                          // starting at 0. Duplicates and regressions
                                          // are rejected as CreditReplay (§5.4.5).
  sig:           Ed25519Signature,        // invoker's signature; preimage below
}
```

**`caveats_binding` preimage.** The binding commits the stream open to the exact set of caveats the UCAN was narrowed to at check time **and** pins the open to this specific stream instance so a binding computed for one open cannot be replayed into another:

```
caveats_binding = SHA-256(
  "SCP-OUTLET-CAVEAT-BIND-V1:"
  || len_be32(ucan_cid)                 // 4-byte big-endian length
  || ucan_cid                            // CID of the opening UCAN (bytes)
  || request_id                          // 16 bytes, the stream's request_id (fixed width)
  || len_be32(invoker_did)               // 4-byte big-endian length
  || invoker_did                         // DID string bytes, UTF-8
  || estimated_chunk_count_be            // 4 bytes, big-endian, from OutletStreamOpen
  || len_be32(canonical_jcs_of_caveats)  // 4-byte big-endian length of the JCS bytes
  || canonical_jcs(effective_caveats)    // narrowed InvocationCaveats, incl. origin_kind
)
```

where `effective_caveats` is the `InvocationCaveats` record (§7.3.8) after all delegation-chain narrowing has been applied, and `canonical_jcs_of_caveats = canonical_jcs(effective_caveats)` (the same bytes consumed as the final field). The final variable-length `canonical_jcs(effective_caveats)` term is length-prefixed per §9.5.1's uniform construction rule — without the prefix, a preimage-collision class exists where a carefully chosen suffix of one caveat-set's JCS bytes could be reinterpreted as the prefix of the following field if a later extension of the preimage added one. The binding commits to (a) the exact token (`ucan_cid`), (b) this stream instance (`request_id`), (c) the invoker identity (`invoker_did`), (d) the invoker-declared billable-chunk ceiling (`estimated_chunk_count`), and (e) the narrowed caveats. `origin_kind` (§7.3.8) is covered automatically via the `canonical_jcs(effective_caveats)` term. A later `OutletStreamOpen` received with the same `request_id` and a different `caveats_binding` is rejected as `OutletErrorClass::Authorization::AttenuationViolation`; the runtime pins `(request_id → caveats_binding)` at first open for the TTL of the stream (see "Binding-pinning invariant" below). The `SCP-OUTLET-CAVEAT-BIND-V1:` separator is registered in §9.18.2. This preimage is the first to ship — no prior `V` numbering existed outside drafts.

**JCS `Option` serialization rule (cross-SDK byte-for-byte match).** Absent `Option`-typed fields in `effective_caveats` — `amount_max_per_call`, `amount_max_cumulative`, `valid_from`, `valid_until`, `hours_of_day`, `days_of_week`, `max_calls`, `rate_window`, `input_schema`, `allowed_adapters`, `allowed_target_dids`, `origin_kind` when absent — are **OMITTED** from the JCS encoding, NOT serialized as explicit `null`. Concretely, `canonical_jcs(effective_caveats)` applies standard serde-with-`skip_serializing_if = "Option::is_none"` semantics before running RFC 8785 canonicalization: a `None`-valued field produces no key-value pair in the JSON object, and RFC 8785's lexicographic sort then orders only the present keys. An SDK that serializes `None` as `"field_name": null` produces a distinct byte string and a distinct `caveats_binding` preimage, and the resulting stream-open is rejected. All four SDKs MUST use the omit-none convention. A cross-SDK conformance fixture covers this: a caveat set `{ amount_max_per_call: Some(100) }` produces the same 32-byte `caveats_binding` from Python (PyO3), TypeScript (napi-rs), Swift (UniFFI), and Kotlin (UniFFI) regardless of the other 11 fields' absence — verified by `cargo test -p scp-testing --test outlet_caveats_binding_conformance`.

**Binding-pinning invariant.** At first `OutletStreamOpen`, the receiver records `(request_id → {context_id, outlet_id, caveats_binding, stream_epoch, invoker_pk, credit_counter, monotonic_seq_cursor})` in its stream table for the lifetime of the stream (bounded by `timeout_ms`, `stream_credit_stall_secs`, or terminal chunk arrival, whichever fires first). `stream_epoch` is the hosting context's MLS epoch counter at acceptance (§6.2.1.1(e)) and is the value committed into the `SCP-OUTLET-CREDIT-V1:` grant preimage — pinning it in the stream table lets the executor reject credit grants whose preimage epoch does not match the stream's accept-time epoch even if `request_id` and `caveats_binding` are colliding across a binding-eviction race. Any subsequent `OutletStreamOpen` carrying the same `request_id` but a different `caveats_binding` is rejected as `AttenuationViolation`. This closes the "two opens with the same request_id under different caveats" attack without relying on undetectable later-chunk inspection. The per-stream `CreditCounterStore` entry shares the pinning record's lifetime — the credit counter and `monotonic_seq_cursor` are stored alongside the pinned `caveats_binding` so a single eviction signal (stream terminated, timeout fired, credit-stall cancel) clears both at once. Once the stream terminates, the receiver MAY evict the pinning record and associated credit state; a fresh `request_id` is required for a new stream.

**Per-context concurrent-stream bounds.** Each context enforces three independent ceilings on inbound streams, enforced at `OutletStreamOpen` acceptance:

| Parameter | Default | Range | Mechanism |
|-----------|---------|-------|-----------|
| `max_concurrent_inbound_streams_per_invoker` | 8 | [1, 1024] | Maximum number of streams the *immediate-previous-hop* invoker DID may have open concurrently against any outlet in the context. Breach rejects the open with `OutletErrorClass::Transport::RateLimited` slug `transport.concurrent-streams-per-invoker`. |
| `max_concurrent_inbound_streams_per_origin_invoker` | 16 | [1, 1024] | Maximum number of streams the *outermost caller DID in the delegation chain* may have open concurrently against any outlet hosted by this operator DID (tracked at operator scope, not per-context, so a caller cannot fan out across a cluster of interfaces hosted by the same operator to bypass the per-context limit). The outermost DID is the `iss` of the root UCAN in the delegation chain presented at open. Breach rejects with `OutletErrorClass::Transport::RateLimited` slug `transport.concurrent-streams-per-origin-invoker`. |
| `max_concurrent_inbound_streams_per_outlet` | 128 | [1, 1024] | Maximum number of streams open concurrently against a single outlet (across all invokers). Breach rejects the open with `OutletErrorClass::Transport::RateLimited` slug `transport.concurrent-streams-per-outlet`. |

All three are `ContextParams` fields, registered in §9.18.B. The immediate-invoker ceiling bounds the DoS surface a single neighbor can mount against a single context. The origin-invoker ceiling is tracked by the operator across every interface it hosts and bounds fan-out from a single origin regardless of delegation-chain rewriting: a caller who narrows a UCAN through N intermediate agents cannot open `N × per_invoker` streams against one operator because the operator groups concurrent streams by the outermost `iss`. The outlet ceiling bounds total fan-in to any one outlet regardless of how many invokers participate. A rejected open does NOT advance `credit_window` or allocate escrow — the acceptance check runs before any stream-table insertion.

**Concurrent-stream counter increment ordering.** The operator's concurrent-stream counter for each of the three ceilings is incremented ATOMICALLY AFTER the full UCAN delegation chain validation completes successfully (§7.2.1 steps 1 through 11) AND after the cap check itself confirms headroom — NOT speculatively at the start of `OutletStreamOpen` processing. Counter increment ordering is:

1. Parse `OutletStreamOpen`; extract `invoker_did`, outermost `iss` (for the per-origin-invoker counter), outlet_id.
2. Run the full UCAN validation pipeline (steps 1-11) to completion. A failing validation returns the corresponding `OutletErrorClass::Authorization::*` and does NOT touch any counter.
3. Run the three cap comparisons in lexical order (per-invoker → per-origin-invoker → per-outlet). A breach at any tier returns the matching `Transport::RateLimited` slug and does NOT increment any counter. Partial increments across tiers are forbidden — a per-invoker success followed by a per-origin-invoker failure leaves all three counters unchanged.
4. On full success (validation + all three caps clear), atomically increment all three counters under a single critical section, insert the stream into the stream table, and begin serving.
5. On terminal chunk emission or cancel-ack, decrement all three counters atomically in the same critical section that evicts the stream-table entry.

This ordering closes the slot-burn DoS where a forged-`iss` open that fails UCAN validation would nonetheless have consumed a per-origin-invoker slot against the real DID named in `iss`. Validation is paid for by the operator (CPU); slot occupancy is paid for by the real `iss` holder. Increment-before-validate would let a low-cost forged-open starve a high-value caller's concurrent-slot budget. Increment-after-validate means the real caller only pays for opens that pass validation.

See also the cross-context streaming section (§6.2.0.5) which cites these parameters at cross-context acceptance.

**Per-chunk operator signature.** Every `OutletStreamChunk.sig` is the operator's Ed25519 signature over

```
SHA-256(
  "SCP-OUTLET-CHUNK-SIG-V1:"
  || len_be32(context_id)             // 4-byte big-endian length
  || context_id                        // UTF-8 bytes of the hosting context's id
  || len_be32(outlet_id)               // 4-byte big-endian length
  || outlet_id                         // UTF-8 bytes of the outlet id
  || request_id                        // 16 bytes, fixed width
  || sequence_be                       // 8 bytes, big-endian
  || caveats_binding                   // 32 bytes, the stream's caveats_binding
  || SHA-256(canonical_jcs(payload))   // 32 bytes
)
```

Per-chunk signing closes the **equivocation** gap: without per-chunk signatures, an operator could stream one sequence of chunks to one member and a different sequence to another, then commit a `stream_manifest_hash` that covers only one of the streams. With per-chunk signatures, a mismatch between what a member received and what the committed manifest covers is cryptographically detectable by that member. Binding `context_id`, `outlet_id`, and `caveats_binding` into the preimage closes the cross-outlet and cross-stream replay surface: a chunk signed for outlet X in context A with caveats C cannot be presented as a valid chunk of a stream targeting outlet Y in context B or bearing a different caveat set, even if a `request_id` collision were contrived. The `SCP-OUTLET-CHUNK-SIG-V1:` separator is registered in §9.18.2. This preimage is the first to ship — no prior `V` numbering existed outside drafts.

**Credit-based backpressure.** Each stream opens with `credit_window` chunks of headroom. The executor may emit up to that many Data/Progress chunks before it must wait for an `OutletStreamCredit` grant. End and Error are terminal and do NOT consume credit — an executor can always close a stream. The default window is `ContextParams::stream_window_default` (default 32). Consumers grant credit as they process chunks. A stream whose credit reaches zero and is not replenished within `stream_credit_stall_secs` (default 30) is cancelled with `OutletErrorClass::Execution::CreditStall`.

**Credit grant signature.** Every `OutletStreamCredit` MUST carry the invoker's Ed25519 signature in `sig`, over the preimage:

```
SHA-256(
  "SCP-OUTLET-CREDIT-V1:"
  || len_be32(context_id)         // 4-byte big-endian length
  || context_id                    // UTF-8 bytes of the hosting context's id
  || len_be32(outlet_id)           // 4-byte big-endian length
  || outlet_id                     // UTF-8 bytes of the outlet id
  || request_id                    // 16 bytes, fixed width
  || grant_be                      // 4 bytes, big-endian (u32 grant)
  || monotonic_seq_be              // 8 bytes, big-endian (u64 monotonic_seq)
  || stream_epoch_be               // 8 bytes, big-endian (u64 stream_epoch —
                                   //   the hosting context's MLS epoch counter
                                   //   at OutletStreamOpen acceptance, per
                                   //   §6.2.1.1(e); pinned in the stream record
                                   //   alongside caveats_binding at first open)
  || caveats_binding               // 32 bytes, the stream's caveats_binding
)
```

The executor's credit accounting admits a grant only if (a) the signature verifies under the invoker's public key recorded at stream open, (b) `context_id`, `outlet_id`, `stream_epoch`, and `caveats_binding` bound into the preimage match the pinned values for this `request_id` at first open, and (c) `monotonic_seq` strictly exceeds every previously accepted `monotonic_seq` for this `request_id`. Binding stream identity (`context_id`, `outlet_id`, `caveats_binding`, `stream_epoch`) into the signed preimage closes the cross-stream and cross-epoch replay surface: a grant signed for stream A in context X at epoch E cannot be replayed as a valid grant for stream B in context Y or for a different epoch even under contrived `request_id` collisions or binding-eviction races. Duplicates and regressions are rejected as `OutletErrorClass::Authorization::CreditReplay` and do NOT advance the credit counter. This closes the relay-drop/inject DoS surface: a malicious relay cannot forge grants to starve the executor, and cannot replay stale grants to bypass the invoker's intended flow control. The `SCP-OUTLET-CREDIT-V1:` separator is registered in §9.18.2.

**Credit-grant escrow top-up.** Each validly accepted `OutletStreamCredit` grant on an Action outlet with `cost.amount > 0` automatically tops up the stream's escrow by `cost.amount × grant`, computed via `checked_mul` — arithmetic overflow rejects the grant with `OutletErrorClass::Economic::EscrowOverflow` and does NOT advance the credit counter. If the invoker's available balance is below the top-up amount at the moment of grant acceptance, the grant is rejected with `OutletErrorClass::Economic::InsufficientFunds` and the credit counter does not advance. The operator only bills chunks emitted while covered by topped-up escrow; a grant that fails top-up does not authorize further billable chunks. For Query outlets and zero-cost outlets no top-up is performed.

**Ordering and gaps.** `sequence` values are strictly monotonic per `request_id`. A receiver that observes a gap (missing sequence) MUST cancel the stream with `OutletErrorClass::Execution::StreamGap` and SHOULD rerun. MLS has no primitive for per-message retransmit and adding one at the SCP layer would require reintroducing a per-recipient unicast channel that MLS deliberately eliminates — so the mitigation is cancel-and-rerun, not retry.

**UCAN check locus.** The UCAN presented in `OutletStreamOpen` is validated exactly once, at open. Every chunk carries the `request_id`; the receiver correlates to the open and does not re-present or re-validate. This prevents UCAN revocation races mid-stream from splitting a stream into authorized and unauthorized halves.

**Revocation re-check cadence (receiver-side).** Because an executor may never voluntarily reach a checkpoint, the stream receiver's SDK framework MUST enforce its own periodic re-check of the opening UCAN's revocation status during the entire active lifetime of the stream. Every `ContextParams::stream_ucan_recheck_secs` (default 10, range [1, 60]; registered in §9.18.B) the framework consults its revocation state and, if the token has been revoked since stream open, terminates the stream with `OutletErrorClass::Authorization::RevokedMidStream` (code `SCP-TOOL-6110`, slug `authorization.revoked-mid-stream`) regardless of whether the executor has voluntarily reached a checkpoint. Already-emitted chunks remain authorized; the stream closes at or before `stream_ucan_recheck_secs` after the revocation event regardless of executor behavior. The executor also MAY re-check at its own checkpoints; the framework-side cadence is the worst-case upper bound on exposure and is not dependent on executor cooperation. SDK wrappers for `invoke()` are responsible for plumbing this re-check task into the stream's lifecycle.

**Context teardown vs. revocation (round 8).** The same framework re-check loop that enforces the revocation cadence above also observes the hosting context's liveness. When the hosting context is closed or the operator is evicted/leaves while a stream is active, the framework terminates the stream with `OutletErrorClass::Protocol::ContextClosedMidStream` (code `SCP-TOOL-6101`, slug `protocol.context-closed-mid-stream`) — NOT with `RevokedMidStream` (Authorization class). The two conditions are distinct and MUST NOT be conflated:

- **Revocation** (`authorization.revoked-mid-stream`, Authorization class) means the *invoker's UCAN* was revoked. It is an authorization-boundary event and the correct audit signal is "the caller's right to invoke was withdrawn."
- **Context teardown** (`protocol.context-closed-mid-stream`, Protocol class) means the *hosting context* ceased to exist underneath an otherwise-valid authorization. The caller's UCAN was never revoked; the stream ended because its substrate disappeared.

Mapping a teardown to `RevokedMidStream` would (a) write a false audit signal — a behavioral record implying the caller's credential was revoked when it was not — and (b) hand an adversary a DoS lever: an operator able to trigger a teardown (e.g., by leaving the context) could synthesize a revocation-class audit entry against an arbitrary in-flight invoker. Round 8 closes this by giving teardown its own Protocol-class terminal cause. When both conditions are observable in the same re-check tick (a context closed AND the token revoked), **context teardown takes precedence** — the stream's substrate is already gone, so the Protocol-class teardown is the more proximate and accurate cause.

**Node-level concurrent-pump ceiling (round 8).** Distinct from the three per-context `OutletStreamOpen` admission caps (per-invoker / per-origin-invoker / per-outlet) above, each node enforces a single node-wide ceiling on the total number of concurrently-running stream pumps across all contexts hosted on that SCP instance, governed by `max_concurrent_outlet_stream_pumps` (default 4096, range [1, 65536]; per-instance state per ADR-048 — NOT a process-global). The ceiling bounds the runtime's aggregate task/memory footprint regardless of how the per-context caps are configured across many contexts. A permit is acquired AFTER all per-context admission/escrow/binding gates pass; on saturation the open is hard-rejected with `OutletErrorClass::Execution::StreamCapExhausted` (code `SCP-TOOL-6131`, slug `execution.stream-cap-exhausted`) and no stream-table entry, escrow reservation, or admission counter is mutated. The permit is held for the exact lifetime of the pump task and released when the pump exits — normal close, terminal chunk, cancel-ack, or panic — so a panicking pump cannot leak a permit. A rejected open does not consume a permit.

**Cancellation and billing boundary.** The existing `OutletCancel` message cancels a stream by `request_id`. The executor-side framework handles `OutletCancel` receipt as follows: (1) it records `cancel_ack_seq = current emission cursor` (the next-to-emit sequence number, pinned at the moment of cancel arrival, so chunks already in flight at that sequence are NOT counted as billable above the cutoff); (2) it arms the `stream_cancel_ack_secs` timer (default 5s); (3) it emits exactly one terminal chunk (`End` or `Error { terminal: true }`) within the window — this terminal chunk is the **cancel-ack**, and its `sequence` is the authoritative **cancel-ack sequence** written into the event log; (4) on terminal chunk emission the framework flushes stream state (clears the pinning record from the stream table, releases escrow, releases the chain-depth slot). If the timer fires before the executor emits a terminal chunk, the framework forces the stream closed with `OutletErrorClass::Execution::CancelAckTimeout` (code `SCP-TOOL-6135`, slug `execution.cancel-ack-timeout`) and writes its own terminal `Error { terminal: true }` chunk at the next-to-emit sequence. A receiver MAY ignore chunks with sequence greater than the cancel-ack sequence, but the executor MUST NOT emit Data/Progress chunks with sequence greater than the cancel-ack sequence.

**Cancel signature (round 7 cancel-auth tightening).** Every streaming `OutletCancel` MUST carry the invoker's Ed25519 signature in `sig`, over the preimage:

```
SHA-256(
  "SCP-OUTLET-CANCEL-V1:"
  || len_be32(context_id)         // 4-byte big-endian length
  || context_id                    // UTF-8 bytes of the hosting context's id
  || len_be32(outlet_id)           // 4-byte big-endian length
  || outlet_id                     // UTF-8 bytes of the outlet id
  || request_id                    // 16 bytes, fixed width
  || next_seq_be                   // 8 bytes, big-endian (u64 — runtime-derived)
  || caveats_binding               // 32 bytes, the stream's caveats_binding
)
```

The `next_seq` field bound into the preimage is the **runtime's** current next-to-emit cursor at the moment the cancel is signed — never a value supplied by the caller. Implementations MUST read this value from the live runtime state (the dispatch pump's emission counter, exposed via `StreamSessionHandle::current_next_emission_seq` or equivalent) and bind that exact byte sequence into the preimage. A bridge that accepts a caller-input `next_seq` lets the caller forge `cancel_ack_seq` (zero to nullify billing of delivered chunks; `u64::MAX` to over-bill); for the same reason, a runtime that records `cancel.next_seq` verbatim without cross-checking against its own cursor would absorb the forgery. The runtime accepts a streaming cancel only if the signature verifies under the invoker's public key pinned at stream open (the same `invoker_pk` recorded for credit-grant verification). A cancel whose signature does not verify, or whose preimage fields do not match the pinned `(context_id, outlet_id, caveats_binding)` triple for this `request_id`, is rejected as `OutletErrorClass::Authorization::AuthorizationFailed` and does NOT mutate stream state — neither the cancel-ack timer arms nor `cancel_ack_seq` is recorded. Without this signature, a malicious relay or eavesdropping member could forge cancels keyed only on observed `request_id` values and force-terminate streams the invoker did not authorize. Binding stream identity (`context_id`, `outlet_id`, `caveats_binding`) into the preimage closes the cross-stream replay surface — a cancel signed for stream A in context X cannot be replayed against stream B or against a different caveat shape, even under contrived `request_id` collisions. The `SCP-OUTLET-CANCEL-V1:` separator is registered in §9.18.2.

**FFI bridge caller authentication (CRITICAL #1 / SCP-OUT-037 round-8).** Every FFI bridge that exposes the streaming control plane (`outlet_stream_grant_credit`, `outlet_stream_cancel`, `outlet_stream_terminate`) MUST require the caller to identify itself via a `caller_did` parameter and verify the value matches the `invoker_did` pinned at stream open before signing under the registry-held invoker key. Without this gate, any in-process code that observes a `request_id` could drain credit, force-cancel, or terminate any concurrent stream — the round-7 signature gates above are vacuous because the bridge wields the signing key on behalf of the caller. The verification SHOULD slug as `authorization.denied` (`SCP-PERM-3001`) on mismatch; the runtime layer's signature check remains in force as defense-in-depth.

**Billing semantics.** Streaming-native invocation uses an escrow-and-reconcile model so early termination does not leave the economic layer inconsistent.

- **At open** (Action outlets with non-zero cost only): the runtime escrows an upper-bound estimate from the invoker's balance. The estimate is `cost.amount × estimated_chunk_count`, computed via `checked_mul` — an arithmetic overflow is rejected as `OutletErrorClass::Economic::EscrowOverflow` before any state is committed. `estimated_chunk_count` is declared in the open and is structurally bounded by `min(credit_window, caveats.max_calls.unwrap_or(u32::MAX))` — a declared estimate exceeding that bound is rejected at open with `OutletErrorClass::Input::EstimateExceedsBound` (the bound is the protocol's upper limit on how many billable chunks CAN flow regardless of executor behavior, so the escrow must not over-reserve beyond it). For outlets without declared cost or for Query outlets, escrow is zero and `estimated_chunk_count` is advisory.
- **Per chunk**: the operator accrues `cost.amount` per billable chunk (Data chunks; Progress, End, Error are never billed). Chunks beyond the cancel-ack sequence are NOT billed even if they arrive (the operator violated cancel semantics; the invoker does not pay for the violation).
- **At close** (`End` received or stream terminated): the runtime issues a `PaymentReceipt` (§19.15.5) for the billed amount and refunds the unspent escrow to the invoker. A stream that terminates with `Error { terminal: true }` before any Data chunk refunds the full escrow; the operator does not bill for the failed execution.
- **Credit-stall cancel**: the stall cancel (`SCP-TOOL-6133`) releases the escrow and the chain-depth slot. The operator is billed for Data chunks already delivered within the stalled window.

The event log records `chunks_billed: u32` separately from `stream_chunk_count`: the total chunk count includes Progress/End/Error, while `chunks_billed` is the count of Data chunks at or below the cancel-ack sequence that were validly delivered.

**`chunks_billed` is verifiable from the manifest.** Every leaf of the chunk manifest commits to a canonical chunk whose `payload` carries the `@type` discriminator (§5.4.5 wire types). For any event whose `stream_manifest_hash` and chunk sequence are known, an auditor computes the reference count

```
chunks_billed_ref = |{ i : leaf_i.payload."@type" == "data" && i <= cancel_ack_seq }|
```

The event log's recorded `chunks_billed` MUST equal `chunks_billed_ref`. An `OutletInvokedEvent` whose recorded `chunks_billed` does not match the value derivable from the manifest root, the sealed chunk sequence, and the cancel-ack sequence is a wire-layer rejection — the event is refused at log-insert time, not accepted-and-flagged. The cancel-ack sequence is recorded alongside `stream_terminal_status` in the event (absent when the stream terminated without cancel, in which case the ceiling is `u64::MAX` and the predicate reduces to `@type == "data"`). Because leaves cover the full canonical chunk including `@type`, `sig`, and the `caveats_binding` committed at chunk-signing, `chunks_billed_ref` is a function of the signed, committed stream — operators cannot over-bill by recording a higher count than their own signed manifest supports, and cannot under-bill without making a manifest that excludes already-delivered chunks.

**Cross-context streaming.** Streams span the §6.2 tool-interface boundary. A shared-member bridge re-encrypts each chunk per-recipient as it crosses. `chain_depth` is set at open and inherited by every chunk (chunks do not recompute or check it). Credit is end-to-end: the originating invoker grants credit that propagates across the bridge.

**Event log shape.** A stream produces ONE `OutletInvokedEvent` at close, not one per chunk. The event carries:

```
OutletInvokedEvent {
  // Existing fields retained (invoker_did, outlet_id, input_hash, ...)
  stream_chunk_count:     u32,        // total chunks including terminal
  chunks_billed:          u32,        // Data chunks at or below cancel-ack sequence
  stream_manifest_hash:   [u8; 32],   // Merkle root over chunk leaves; see below
  stream_terminal_status: StreamTerminalStatus, // Ok | Error(code) | Cancelled
}
```

**Chunk manifest leaf construction.** The manifest is a Merkle tree over the ordered chunk sequence using RFC 6962 tag bytes to prevent second-preimage collisions between leaves and interior nodes:

```
leaf_i = SHA-256(
  "SCP-OUTLET-CHUNK-V1:"
  || 0x00                         // RFC 6962 leaf tag
  || canonical_jcs(chunk_i)       // covers request_id, sequence, payload, sig
)

interior = SHA-256(
  "SCP-OUTLET-CHUNK-V1:"
  || 0x01                         // RFC 6962 interior tag
  || left_hash                    // 32 bytes
  || right_hash                   // 32 bytes
)

stream_manifest_hash = root of the resulting binary tree
```

The `SCP-OUTLET-CHUNK-V1:` separator is registered in §9.18.2. The leaf covers the full canonical chunk including `sig`, so a later verifier holding a chunk and a manifest root can prove the operator signed that exact chunk.

**Inclusion proofs.** The `stream_manifest_hash` is a commitment to the chunk sequence. A chunk is provably part of the recorded stream iff a verifier holding the chunk, the chunk's index, and the root can reconstruct a valid Merkle path. Inclusion and consistency proofs over this tree follow **RFC 6962 §2.1 (audit paths)** using the same leaf/interior tag-byte construction defined above — the algorithm is pinned at the protocol level even while the SDK-surface API for retrieving proofs is deferred. A per-chunk inclusion-proof API (`outlets.inclusion_proof(invocation_id, chunk_index) → path`) is the **only** deferred piece; the manifest root commitment and the audit-path algorithm are both protocol-level invariants, so auditing tools can reconstruct proofs off-line by replaying the event log and the retained chunk sequence using a standard RFC 6962 verifier. The SDK API deferral is tracked in discussion [#1698](https://github.com/limn-works/scp/discussions/1698).

**Classification orthogonality.** Both Query and Action outlets stream.

**Non-streaming invocation.** A non-streaming invocation is a stream that emits exactly two chunks: `Data(output)` followed by `End(output)`. SDKs MAY present a synchronous `invoke()` surface that collects the stream into the final `End.aggregate`, but the wire contract is always the streaming form.

**Rejected alternatives (for this section).** (1) A separate `OutletResponse` non-streaming type: rejected because every invocation would need to advertise its response shape (stream vs. one-shot) at registration, and the protocol would fork into two invocation pipelines with almost-but-not-quite identical semantics. Collapsing to streaming with a two-chunk degenerate case is simpler. (2) Per-chunk inclusion-proof API exposed on the SDK surface: deferred per above. The manifest root is sufficient for integrity; a proof API is a convenience over that primitive and can be added without a wire break. (3) Per-chunk UCAN checks: rejected because mid-stream revocation would split a single logical invocation into authorized and unauthorized halves, which is less legible than revoking-at-checkpoint.

## 5.5 Roles

Contexts define roles with specific permission sets within the capability ceiling. Roles determine which tools an agent can invoke, what data it can access, whether it can invite others, modify settings, etc.

Properties of roles:

- **Visible before opt-in.** You see what role you'd get before joining.
- **Non-negotiable.** Agents cannot request or bargain for different roles. Take it or leave it. If you want a different role, ask the context creator (human to human) or create your own context.
- **Defined by context creator.** Custom roles beyond defaults are context-specific.
- **Governed by context governance model.** Role changes require whatever governance the context uses.

**Broadcast context roles.** Broadcast contexts (§5.14) extend the role system with two mode-specific roles that reuse existing primitives:

- **Author** — holds `messages:write` UCAN. Can publish broadcast-key-encrypted content. Authors are bounded (added via `role:assigned` events with role `author`). Each author maintains their own broadcast key with an independent epoch counter.
- **Subscriber** — holds `messages:read` (auto-granted on DID-authenticated registration in open broadcast contexts, or requiring an explicit admin-issued UCAN in gated broadcast contexts). Subscribers receive author broadcast keys on request. Subscribers are unbounded.

The author/subscriber distinction mirrors the writer/reader two-tier model from contexts with discovery tools (§6.2.2B). Open broadcast subscriber registration follows the same DID-authenticated pattern as context reader-tier access.

### 5.5.1 Default Role Set

Every context has a minimum set of built-in roles. Context creators MAY define additional custom roles, but these four are always present:

| Role | Permissions | Description |
|------|------------|-------------|
| `admin` | All capabilities in ceiling + `member:invite` + `member:remove` + `role:assign` + `governance:propose` + `governance:vote` + `metadata:edit` | Full control. The context creator is always assigned this role at creation. |
| `moderator` | `messages:read` + `messages:write` + `outlet:query:*` + `outlet:call:*` + `member:remove` + `governance:propose` | Can moderate content and members but cannot change roles or governance structure. |
| `member` | `messages:read` + `messages:write` + `outlet:query:*` + `outlet:call:*` | Standard participant. Can read, write, and invoke outlets. |
| `observer` | `messages:read` | Read-only access. Cannot send messages, invoke outlets, or participate in governance. Observers can see all content and membership but cannot create state. |

**Observer role permissions (detailed):**

Observers can:
- Read all messages in the context (subject to memory scope and access key restrictions).
- View the member list, roles, and context metadata.
- View outlet registrations and their schemas.
- View the event log (governance actions, membership changes).
- Leave the context voluntarily.

Observers cannot:
- Send messages or reactions.
- Invoke outlets (no `outlet:query:*`, `outlet:query:{id}`, `outlet:call:*`, or `outlet:call:{id}`).
- Invite members.
- Propose or vote on governance actions.
- Modify context metadata.
- Register or deregister outlets.

**Custom roles.** Context creators define custom roles by specifying a role name (string, max 64 chars, `[a-z0-9_-]`) and a permission set (subset of the ceiling). Custom role permissions MUST be a subset of the ceiling — a custom role cannot grant capabilities beyond the ceiling. Custom roles are stored in the context's role registry (`context/{id}/role/{role_name}` per §17.3) and visible in context metadata.

## 5.6 Membership

One agent per human per context. Membership is transparent — participants can see the member list, roles, and agent capability metadata. When you opt into a context, you know what you're walking into.

**Broadcast context membership.** Broadcast contexts use a two-tier membership model: authors (MLS-equivalent bounded writers) and subscribers (unbounded readers registered via DID-signed requests). Subscriber registration records membership via `MemberJoined` events with role `subscriber`. The member list includes both tiers. Subscriber count is visible in metadata.

## 5.7 Metadata

Context metadata follows a two-tier visibility model that balances legibility (informed consent before joining) with privacy (operational details that may be sensitive).

**Structural fields** (always visible — required for informed consent):

- Template ID, if created from a well-known template (§5.12)
- Capability ceiling and ceiling policy (`immutable` or `governed`, §5.3)
- Available roles and their permission sets
- Governance model
- TTL / time-to-live, if set (§5.10)
- Promotion policy (`no_promotion` or `promotable`), if context has a TTL (§5.10)
- Memory scope (§5.11)
- Context mode (`Encrypted` or `Broadcast`, §5.14)
- Active bridges: `Vec<BridgeMetadata>` where each entry describes an active bridge connector registered with the context (§12.2). Bridge metadata is structural because bridge presence materially affects trust evaluation and privacy — a participant cannot give informed consent without knowing that content may flow to an external platform. Bridge metadata is updated whenever a bridge is registered, revoked, or suspended.
- Metadata visibility policy itself (so prospective members know what's hidden)

Structural fields are always public regardless of `MetadataVisibilityPolicy`. These are the parameters a prospective member needs to evaluate whether to join — hiding them would undermine informed consent.

**Operational fields** (governed by `MetadataVisibilityPolicy`):

- Member count
- Context age
- Creator identity
- Name
- Description
- Economic policy, if set (§19.3) — pricing, accepted adapters, payee
- Active tool interface count (inbound and outbound, §6.2, §9.2.1)
- For child contexts (§5.13): parent context IDs, parent metadata summaries, parent governance configuration, and the prospective member's eligibility basis (§5.13.6)

Each operational field has a visibility of `PreJoin` (visible to anyone with the context_id) or `MemberOnly` (visible only to context members). The `MetadataVisibilityPolicy` is declared at context creation and follows the context's ceiling policy — immutable or governed via `ModifyCeiling`.

```rust
/// Controls whether a metadata field is visible before joining.
pub enum FieldVisibility {
    PreJoin,    // Visible to anyone with context_id
    MemberOnly, // Visible only to context members
}

/// Per-field metadata visibility policy.
pub struct MetadataVisibilityPolicy {
    pub member_count: FieldVisibility,
    pub context_age: FieldVisibility,
    pub creator_identity: FieldVisibility,
    pub name: FieldVisibility,
    pub description: FieldVisibility,
    pub economic_policy: FieldVisibility,
    pub outlet_interface_count: FieldVisibility,
    pub child_context_info: FieldVisibility,
}

/// Metadata for an active bridge connector (§12.2).
/// Structural field — always visible before joining.
pub struct BridgeMetadata {
    /// External platform name (e.g., "discord", "slack", "x").
    pub platform: String,
    /// DID of the bridge operator — the human accountable for
    /// bridge behavior (§12.2).
    pub bridge_did: DID,
    /// Capabilities the bridge exercises in this context.
    /// Subset of: "relay_messages", "create_shadows",
    /// "attest_identities", "forward_presence".
    pub capabilities: Vec<String>,
    /// Directionality of the bridge.
    pub mode: BridgeDirectionality,
}

/// Whether the bridge relays content in both directions or one.
pub enum BridgeDirectionality {
    /// Platform-to-SCP and SCP-to-platform.
    Full,
    /// Platform-to-SCP only (external content enters SCP,
    /// but SCP messages are not forwarded to the platform).
    ReadOnly,
    /// SCP-to-platform only (SCP messages are forwarded to the
    /// platform, but no external content enters SCP).
    WriteOnly,
}
```

Default: all fields `PreJoin` (backward-compatible — existing contexts expose everything). Well-known templates override defaults per template (§5.12.1). For example, `bilateral-ephemeral` defaults member_count, context_age, and creator_identity to `MemberOnly`; `public-broadcast` defaults all fields to `PreJoin`.

When a template ID is present, the joining party can evaluate the context with a single template-level check rather than inspecting each parameter individually — the template is a commitment that the parameters match the well-known definition exactly (§5.12.1).

### 5.7.1 Metadata Publication and Retrieval

Contexts publish their parameters to a publicly derivable routing address, enabling pre-join inspection per the legibility principle (§1). The metadata routing address is derived deterministically from the context ID:

```
metadata_routing_id = SHA-256(context_id || "scp-metadata")
```

Published metadata includes structural fields (always) and operational fields filtered by `MetadataVisibilityPolicy`. Fields with `MemberOnly` visibility are omitted from the published metadata record. Members retrieve full metadata through the context's internal state, not the public metadata record.

Prospective members retrieve context parameters by subscribing to the `metadata_routing_id` on the relay without joining the context. The metadata record is signed by a current context admin, enabling verification of authenticity without membership. This makes the legibility guarantee mechanical — any identity with the context ID can derive the metadata address and inspect the context's visible parameters before deciding whether to join.

Metadata updates (e.g., governance-driven ceiling modifications in `governed` contexts) are republished to the same routing address. Relays treat metadata records as standard relay messages — no special relay-side logic is required.

### 5.7.2 Metadata Signing, Freshness, and Replay Protection

**Signing key.** Metadata records are signed by a current context admin's **Active Signing Key (`#active`)** from their DID document. The `#active` key is the human-controlled operational signing key (§3), consistent with its use for governance actions and context management operations. Agent Signing Keys (`#agent`) MUST NOT sign metadata records — metadata publication is a governance-adjacent operation that requires human-accountable authorization.

**Metadata record format:**

```
MetadataRecord {
    context_id:       ContextId,
    sequence:         u64,            // Monotonically increasing, starts at 1
    signer_did:       DID,            // Admin who signed this record
    timestamp:        u64,            // Unix milliseconds, informational (not used for ordering)
    structural:       StructuralMetadata,
    operational:      FilteredOperationalMetadata,  // Filtered by MetadataVisibilityPolicy
    signature:        Ed25519Signature,
}

Signature formula:
Ed25519_sign(active_signing_key, SHA-256(
    context_id || sequence || signer_did || timestamp || serialize(structural) || serialize(operational)
))
```

**Monotonic sequence number.** Each metadata record carries a `sequence` number that increments by 1 on every metadata update. The sequence starts at 1 (the initial metadata record published at context creation). The sequence provides a total ordering of metadata states independent of wall-clock time.

**Replay protection.** Consumers of metadata records (prospective members, relay caches, SDK metadata fetchers) MUST reject any metadata record with a `sequence` number less than or equal to the highest `sequence` they have previously observed for that `context_id`. This prevents a relay or network attacker from serving stale metadata to misrepresent a context's current state (e.g., showing a narrower ceiling that has since been expanded, or hiding a governance model change).

**Signer verification.** A prospective member verifying a metadata record: (1) resolves the `signer_did` via DID resolution (§3), (2) extracts the `#active` verification method, (3) verifies the Ed25519 signature, (4) cannot independently verify that the signer is a current admin without joining (admin status is internal context state). The signature guarantees that the metadata was produced by the claimed DID; the `signer_did` being an admin is a social-layer assurance, not a cryptographic one. Once a member joins and has access to the membership roster and role assignments, they can retroactively verify that the signer held admin status at the time of signing.

**Staleness.** The protocol does not define a hard metadata TTL — metadata validity is determined by the `sequence` number, not by age. However, SDKs SHOULD re-fetch metadata before presenting it to a user for a join decision if the cached record is older than 5 minutes, as a defense-in-depth measure against stale cache attacks.

**Metadata update distribution.** Metadata updates originating from governance actions (e.g., `ModifyCeiling`, `ModifyRoles`) are distributed through two paths: (1) republished to the `metadata_routing_id` for external consumers, and (2) distributed to current members via MLS application messages (Encrypted mode) or relay messages (Broadcast mode) as a `MetadataUpdated` event in the event log. Internal distribution includes the full operational metadata (not filtered by visibility policy) since recipients are already members.

## 5.8 Context Identity

Contexts are cryptographic entities. You opt into a key, not a name. Spoofing a cryptographic identity is hard; spoofing a name is a UI problem for clients to solve.

Human-readable addressing (§22) adds a protocol-level resolution layer — context handles, petnames, attestation-backed handles, and domain handles — that maps human-readable strings to context IDs and DIDs. Handles are resolution hints; the cryptographic context ID remains canonical. Each resolution result carries a trust level (§22.7) indicating the strength of the name-to-identifier binding.

## 5.9 Governance

Contexts support multiple governance models for who can change roles, settings, membership, and other context configuration. Models include but are not limited to: single admin, multi-sig (N-of-M approval), elected moderators, full member consensus, weighted voting.

The governance model is declared at creation and visible to all. Governance implementations are **pluggable** — the protocol defines the `GovernanceEngine` trait (propose, approve, reject) with four concrete models: `SingleAdmin` (single-admin authority), `Threshold` (M-of-N approval), `Majority` (majority vote), and `Unanimity` (full consensus). See ADR-008 (context lifecycle state machine with single-admin governance), ADR-009 (role assignment and capability ceiling enforcement), and ADR-031 (multi-admin governance models) for full specification. Context creators select a governance model at creation; the selection is visible in context metadata (§5.7) and cannot be changed after creation unless the model itself defines a governance transition mechanism.

**Governance execution invariants.** When the `ContextManager` executes an approved governance action, two protocol-level invariants MUST hold:

1. **Proposal-context binding.** A governance proposal's `context_id` MUST match the context it is submitted to for execution. A proposal approved for context A MUST NOT be executable against context B. This prevents cross-context proposal injection — an attacker who obtains an approved proposal from one context cannot replay it against a different context.

2. **Proposal replay protection.** Each context MUST track the set of executed proposal IDs. A proposal that has already been executed MUST be rejected on subsequent submission. This prevents double-execution of approved proposals — even when the underlying operation is idempotent (e.g., blocking an already-blocked author returns `MemberNotFound`), explicit replay detection provides a clean error path and prevents side effects from re-executing event log entries or notifications.

**Content access governance.** Governance controls five content access actions that decouple membership from access (see ADR-031, §9.17):

| Action | Effect | Scope |
|--------|--------|-------|
| `RevokeAccess { did, access: Read }` | Revoke decryption access to context content | `AccessScope::Both` (retroactive + future) or `AccessScope::Read` (read-only) |
| `RestoreAccess { did, capabilities }` | Restore access, forward-only | Future content only — historical gap permanent |
| `RevokeAccess { did, access: Write }` | Revoke publishing authority | `AccessScope::Both` or `AccessScope::Write` |
| `RotateContentKeys { reason }` | Context-wide key rotation | All members, not DID-targeted |

**Membership/access decoupling.** These actions do NOT remove the target from the context. A member with revoked read access remains a member for governance participation and presence but cannot decrypt content. Member states:

| State | In context | Can read | Can write | Can vote |
|-------|-----------|----------|-----------|----------|
| Full member | Yes | Yes | Yes | Yes |
| Read-only member (write revoked) | Yes | Yes | No | Yes |
| Presence-only member (read + write revoked) | Yes | No | No | No |
| Non-member (removed) | No | No | No | No |

Presence-only members lose `governance:vote` and `governance:propose` capabilities alongside content access. A member who can neither read nor write content should not influence governance decisions about content they cannot see. Read-only members retain governance capabilities — they can still observe content and participate meaningfully in governance.

**Redundant operations.** Revoking access for a member whose access is already revoked (same scope) is a no-op that returns success. Restoring access for a member who was never revoked returns `GovernanceError::NothingToRestore`. Revoking with `Write` scope when a `Both` revocation is already active is a no-op (Both subsumes Write). Revoking with `Both` scope when `Write` is active upgrades to Both.

Content access actions go through the context's governance model (propose/vote/execute). In SingleAdmin contexts, the admin's proposal auto-executes. In multi-admin contexts, the action requires the configured quorum. Tiers 1-2 (DID-to-DID blocking) are unilateral identity-layer operations and do NOT go through governance.

**Content scoping.** Granular content access control (e.g., admin-only channels, per-topic areas) uses child contexts (§5.13) as the scoping mechanism. Each "scope" is a child context with its own keys, governance, and membership. Parent governance controls children via `ParentGovernanceConfig`. Tier 3 governance actions are per-context — submit the action to whichever context (parent or child) it applies to.

**Collection size limits.** Governance actions that append to unbounded collections MUST enforce protocol-level maximums to prevent resource exhaustion. Each collection is cloned into `ContextSnapshot` on every mutation, so unbounded growth has quadratic cost. The following limits are protocol-level constants:

| Collection | Maximum | Rationale |
|-----------|---------|-----------|
| `registered_tools` | 256 per context | Tools are heavyweight registrations; 256 exceeds any practical context |
| `tool_interfaces` | 256 per context | Cross-context interfaces are bilateral agreements; 256 exceeds any practical context |
| `threshold_signers` | 64 per context | Signers participate in quorum; >64 is operationally impractical |
| `suspended_capabilities[did]` | No artificial cap | Naturally bounded by ceiling cardinality — at most one entry per capability per member |
| `read_exclusion_list` | No artificial cap | Naturally bounded by membership count — cannot exclude non-members from CEK wrapping |

Implementations MUST return an error (e.g., `LimitExceeded`) when an append would exceed the limit. The error message MUST include the limit value for debuggability.

**String field validation (§9.1A).** User-controlled string fields on governance actions and context metadata are validated at the FFI boundary and at type construction per §9.1A. Specific constraints:

| Field | Location | Max length | Rejects |
|-------|----------|------------|---------|
| `role` / `new_role` | `AddMember`, `ChangeRole` | 256 bytes | Control chars, HTML-special |
| `reason` | `RemoveMember`, `CloseContext`, `BlockAuthor`, `ResetMember`, `RotateContentKeys`, `ProposeContextMigration` | 4096 bytes | Control chars, HTML-special |
| `purpose` | `ApproveSpend` | 4096 bytes | Control chars, HTML-special |
| Context `name` | `PublicMetadata`, `RuntimeMetadata` | 256 bytes | Control chars, HTML-special |
| Context `description` | `PublicMetadata`, `RuntimeMetadata` | 4096 bytes | Control chars, HTML-special |

## 5.10 Context TTL (Time-to-Live)

Contexts gain an optional time-to-live — a declared lifespan after which the context closes automatically. TTL is set at creation and visible in context metadata (visible before opt-in).

When TTL expires:

- Context is closed. No new actions are accepted.
- Encryption keys can be destroyed per the context's memory scope (§5.11), making content physically unreadable.
- **Durable data persists.** The context's existence, its metadata, its participants, and participation record contributions survive. Context is durable data — the interaction inside may be ephemeral, but the fact of the interaction is permanent.

TTL is useful beyond bilateral messaging. Time-boxed brainstorming sessions. Pop-up events. Temporary project groups. Scheduled context expiry for data hygiene. The extension is general-purpose.

**Extension mechanics.** TTL is set at creation. A context's TTL cannot be extended unilaterally. Extension requires agreement from all parties (for bilateral contexts) or through the context's governance model (for multi-party contexts). This prevents one party from unilaterally extending an interaction the other expected to be ephemeral. An expired TTL is final — if participants want to continue, they create a new context (which may reference the closed one for continuity).

**Promotion policy.** Contexts with a TTL also declare a **promotion policy** at creation — whether the context can transition from ephemeral to persistent. The policy is immutable (locked at creation). Two policies:

- **`no_promotion`** (default for ephemeral templates): Context expires per TTL. To continue, create a new context referencing the closed one. Cleanest security model — separate context IDs, separate key material, clear event log boundary.
- **`promotable`**: Context can be promoted to persistent via governance. On promotion: TTL is removed, memory scope transitions from ephemeral to full, existing event log and key material are preserved. Promotion requires consent from **all current members** (not just governance approval) because promotion changes the opt-in contract.

The promotion policy is visible in context metadata (§5.7) before opt-in.

**Interaction with governance.** Governance actions on a TTL'd context follow the same rules as any context — but the TTL acts as a hard upper bound. A governance proposal to extend TTL is valid and follows the context's governance model, but the extension requires explicit consent from all current members (not just governance approval) because TTL was part of the original opt-in contract.

**Key destruction on expiry.** When TTL expires, key destruction follows the memory scope (§5.11). The destruction protocol includes platform-attested verification where available — see §9.15 for the ephemeral key destruction verification mechanism.

### 5.10.1 TTL Extension Governance Protocol

TTL extension is a governance action with additional consent requirements beyond standard governance approval:

1. **Proposal.** An admin submits a `ProposeTTLExtension` governance proposal:
   ```
   ProposeTTLExtension {
     additional_secs: u64,      // Duration in seconds to add to the current TTL
     reason: String,            // Human-readable justification
   }
   ```
2. **Governance approval.** The proposal follows the context's governance model (§5.9). SingleAdmin auto-executes; Threshold/Majority/Unanimity require their configured quorum.
3. **Unanimous member consent.** After governance approval, ALL current members MUST explicitly consent to the extension. Consent is expressed via a signed `TTLExtensionConsent` message (MLS application message):
   ```
   TTLExtensionConsent {
     proposal_id: [u8; 32],     // Hash of the TTL extension proposal
     consented: bool,           // true = consent, false = reject
     signature: Ed25519Signature,
   }
   ```
4. **Consent deadline.** Members have 24 hours to respond. Members who do not respond within 24 hours are treated as having rejected the extension. This prevents indefinite extension of a context that a member expected to be temporary.
5. **Activation.** If all members consent, the TTL is updated. A `TTLExtended` event is recorded in the event log with the old TTL deadline (unix timestamp), new TTL deadline (unix timestamp), proposal ID, and list of consenting members.
6. **Rejection.** If any member rejects (explicitly or by timeout), the extension fails. A `TTLExtensionRejected` event is recorded. The original TTL remains in effect.

**Bilateral context shortcut.** For two-party contexts, TTL extension requires only the other party's consent (the proposer's consent is implicit in the proposal). No governance proposal is needed — a direct `TTLExtensionConsent` exchange suffices.

## 5.11 Memory Scope

Contexts gain a declared memory scope — what happens to the context's data when it closes or expires. Memory scope is set at creation and visible in context metadata (visible before opt-in).

Three scopes:

**Ephemeral.** Context encryption keys are destroyed on close AND the SDK issues deletion requests to relays for all encrypted event data associated with the context. Content is physically unreadable (keys destroyed) and actively cleaned up (ciphertext deleted where relays comply). Durable metadata persists: who participated, when, the declared purpose, participation contributions (participation counts, tool invocations), and discovery provenance. An agent's local orchestration (above the protocol boundary) may retain information from the interaction, but any data the agent subsequently uses elsewhere carries provenance at the protocol level: "sourced from closed ephemeral context."

Relay deletion is best-effort — relays are untrusted infrastructure and cannot be forced to delete. Defense in depth: even if a relay retains the encrypted blobs, the keys are destroyed and the data is unreadable. Relay compliance with deletion requests is tracked as part of relay reliability scoring (§9.9.2) — relays that retain data they were asked to delete are scored lower and deprioritized for future context creation.

**Relay deletion request format.** The SDK issues deletion requests to all relays that store blobs for the closing context. The request uses the relay protocol's existing `DELETE /blobs` endpoint (§10.4):

```
EphemeralDeletionRequest {
  routing_id:   [u8; 32],        // SHA-256(context_id) or HKDF-derived routing ID
  requester_did: DID,            // DID of the member requesting deletion
  context_close_proof: {
    context_id:  ContextId,
    close_event_hash: [u8; 32],  // Hash of the ContextClosed event in the Merkle log
    merkle_root: [u8; 32],       // Current Merkle root of the context's event log
  },
  signature:    Ed25519Signature, // Signed by requester's #active or #agent key
}
```

The relay verifies the signature and MAY verify the close proof against its cached event log state. Relays SHOULD process deletion requests within 60 seconds. The relay responds with a `DeletionAcknowledgement` containing the count of blobs deleted. The SDK retries failed deletion requests with exponential backoff (initial 5s, max 300s, 5 retries) and records relay compliance for reliability scoring.

**Summary.** Context produces a structured summary on close. Full content is destroyed (keys destroyed as with ephemeral). The summary persists with full provenance. Both parties can verify the summary against the event log before keys are destroyed. The summary format is defined by the context (via tools or governance), not by the protocol — the protocol provides the lifecycle hooks (pre-close summary generation, verification window, key destruction) but does not prescribe summary content.

The **verification window** is the period between summary generation and key destruction during which members can verify the summary against the full event log. The verification window duration is 300 seconds (5 minutes). During this window: (a) the summary is published as a signed MLS application message, (b) all members can read the full event log and compare it against the summary, (c) any member can raise a `SummaryDisputed` event if the summary is inaccurate, (d) after 300 seconds with no dispute, key destruction proceeds automatically. If a dispute is raised, key destruction is paused until the dispute is resolved through governance. Disputes that are not resolved within 24 hours result in key destruction proceeding anyway — the 24-hour limit prevents indefinite postponement of an ephemeral context's destruction guarantee.

**Full.** Standard behavior. Context persists indefinitely. No memory restrictions. Content remains accessible to members. This is the default when no memory scope is specified.

**Broadcast context memory scope.** Broadcast contexts support `Full` memory scope only. Ephemeral and Summary scopes require MLS group state destruction for forward secrecy guarantees — broadcast contexts do not have MLS group state. Broadcast key destruction on context close is still performed, but without MLS epoch-based forward secrecy, the security properties of Ephemeral/Summary are weaker. Broadcast-specific ephemeral semantics would require a separate forward secrecy mechanism independent of MLS — this is a non-trivial protocol extension. The current restriction to Full scope is a security-conservative design choice, not a deferral: weakening the ephemeral guarantee by offering it without forward secrecy would be worse than not offering it.

**The Moltbook defense.** Memory scope + provenance tagging (§7.7) prevents time-shifted prompt injection — the attack pattern where malicious payloads are planted in one interaction and activate in a later interaction:

- Ephemeral contexts destroy the source material at the protocol level
- Any data that survives (in agent local memory above the protocol boundary) carries provenance when reintroduced to the protocol: "this came from context X with agent Y"
- Other participants see the provenance and evaluate accordingly
- Fragmented payloads can't reassemble undetected across interactions because each fragment's origin is traceable

**Enforcement honesty.** The protocol enforces memory scope through cryptographic key destruction — specifically, MLS group state destruction (tree secrets, all epoch key schedules, application key material). This is verifiable and absolute for protocol-level data. Platform-attested destruction (§9.15) provides hardware-backed evidence that keys were deleted where available. However, the protocol cannot enforce memory scope above the protocol boundary. An agent's underlying model may retain information from an ephemeral interaction in its own memory. The spec is explicitly honest about this limitation: ephemeral memory scope destroys the protocol-level record and makes reproduction unverifiable, but does not guarantee the agent has forgotten. The absence of provenance on information an agent produces from memory is itself a signal — "this data has no verified origin." Participants in other contexts can evaluate unprovenanced information accordingly.

## 5.11A Context Migration

When a context with an `immutable` ceiling policy (§5.3) needs capabilities beyond its ceiling, or when any context needs to transition to fundamentally different parameters (different governance model, different mode), the protocol path is migration: create a new context and coordinate member transition. Migration is a governance-initiated, member-consented protocol — not an automatic operation.

### 5.11A.1 Migration Initiation

Migration is initiated through a governance proposal of type `ProposeContextMigration`:

```
ProposeContextMigration {
    new_context_params: ContextParams,   // Parameters for the destination context
    reason: String,                       // Human-readable migration rationale
    grace_period: Duration,               // Read-only period for old context (RECOMMENDED: 7 days)
    auto_invite: bool,                    // Whether to bulk-invite all current members
}
```

The proposal follows the context's governance model (§5.9) — SingleAdmin auto-executes, Threshold/Majority/Unanimity require the configured quorum. Migration proposals are logged in the event log.

### 5.11A.2 Destination Context Creation

On proposal approval, the initiating admin creates a new context with the specified `new_context_params`. The destination context:

- Is a fully independent context with its own context ID, MLS group (or broadcast keys), event log, and key material.
- MAY have the same parameters as the source (e.g., same governance model, same roles) or different parameters (expanded ceiling, different governance, different mode).
- Includes a `migration_source` field in its metadata: the source context ID and the governance proposal ID that authorized the migration. This provides provenance for why the destination exists.
- Does NOT inherit the source context's event log, message history, or key material. The destination starts fresh. This is a deliberate security property: new key material means the destination has clean forward secrecy boundaries.

### 5.11A.3 Member Migration

If `auto_invite` is true, the initiating admin sends bulk invitations to all current members of the source context. Members accept or decline individually — migration does not force membership transfer.

**Notification.** All source context members receive a `ContextMigrationProposed` event containing the destination context ID, the migration reason, the grace period, and the new context parameters. This allows members to evaluate the destination before accepting.

**No automatic transfer.** Members are never automatically moved. Each member must individually accept the invitation and join the destination context through the standard join flow. This preserves the opt-in contract: the destination context may have different parameters (expanded ceiling, different governance), and members must consent to those parameters.

### 5.11A.4 Grace Period

After migration is approved, the source context enters a **read-only grace period**:

- **Duration:** Configurable in the proposal. RECOMMENDED default: 7 days.
- **Read-only semantics:** No new messages, tool invocations, or governance actions (except `ProposeContextMigration` cancellation) are accepted. Members can still read existing content and retrieve history.
- **Purpose:** Gives all members time to discover the migration, evaluate the destination, join if desired, and retrieve any data they need from the source.
- **Event log entry:** `ContextMigrationStarted { destination_id, grace_period_end }` is emitted when the grace period begins.

### 5.11A.5 Source Context Tombstoning

After the grace period expires:

- The source context is **tombstoned** — permanently closed with a `ContextTombstoned { destination_id, migration_proposal_id }` event log entry.
- A tombstoned context is closed (no new actions) and carries a permanent pointer to the destination context ID in its metadata. Any identity that resolves the source context's metadata sees the migration destination.
- Key destruction follows the source context's memory scope (§5.11). A context with `Full` memory scope retains readable history after tombstoning. A context with `Ephemeral` scope destroys keys on tombstoning.
- The tombstone record is published to the source context's `metadata_routing_id` so that late-arriving prospective members discover the migration.

### 5.11A.6 Message History

Message history is NOT transferred during migration. The destination context starts with an empty event log. This is intentional:

- **Cryptographic boundary.** The source context's messages are encrypted with the source's MLS group keys (or broadcast keys). Transferring history would require either re-encrypting all messages with the destination's keys (expensive, breaks forward secrecy properties) or sharing source key material with the destination (security violation).
- **Clean provenance.** The destination context's provenance chain starts fresh. Any data brought forward by members carries its own provenance ("sourced from context X").
- **Source remains readable.** During the grace period (and after, if memory scope is `Full`), members can still read the source context's history. The source is not deleted — it is tombstoned.

### 5.11A.7 Migration and Child Contexts

If the source context has child contexts (§5.13):

- Children are NOT automatically migrated. Each child's `on_sever` configuration (§5.13.4) governs what happens when the source context tombstones (which is equivalent to a parent close from the child's perspective).
- If the destination context should parent the same children, new child contexts must be created with the destination as parent. The source context's children and the destination context's children are independent.
- The migration proposal SHOULD document the intended child context disposition for operational clarity.

## 5.12 Context Templates and Lightweight Creation

Context creation requires specifying a ceiling, roles, governance model, memory scope, TTL, and tools. For durable, bespoke contexts this is appropriate — the creator is designing a space. But contexts must also be cheap and disposable. If "spin up a quick context" requires manual configuration of six parameters, agents will route around the protocol for lightweight coordination. Context templates solve this.

### 5.12.1 Well-Known Templates

The protocol defines a set of well-known templates — named parameter bundles with fixed, predictable configurations. Templates are protocol-level identifiers, not SDK convenience wrappers. Both the creator and the joining party recognize the template ID and know exactly what it means without inspecting individual parameters.

```
Template: "scp:template/bilateral-ephemeral"
  ceiling:     [messages:read, messages:write, member:ban]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: ephemeral
  ttl:         required (creator sets duration, no default — forces intentionality)
  tools:       none
  metadata_visibility: { member_count: MemberOnly, context_age: MemberOnly, creator_identity: MemberOnly, name: PreJoin, description: MemberOnly, economic_policy: MemberOnly, outlet_interface_count: MemberOnly, child_context_info: MemberOnly }

Template: "scp:template/bilateral-persistent"
  ceiling:     [messages:read, messages:write, member:ban]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: full
  ttl:         none
  tools:       none
  metadata_visibility: { member_count: MemberOnly, context_age: MemberOnly, creator_identity: MemberOnly, name: PreJoin, description: MemberOnly, economic_policy: MemberOnly, outlet_interface_count: MemberOnly, child_context_info: MemberOnly }

Template: "scp:template/coordination"
  ceiling:     [messages:read, messages:write, outlet:query:*, outlet:call:*, member:ban]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: summary
  ttl:         required (creator sets duration)
  outlets:     creator-defined at creation
  metadata_visibility: { member_count: MemberOnly, context_age: MemberOnly, creator_identity: MemberOnly, name: PreJoin, description: MemberOnly, economic_policy: MemberOnly, outlet_interface_count: MemberOnly, child_context_info: MemberOnly }

Template: "scp:template/group-discussion"
  ceiling:     [messages:read, messages:write, member:invite, member:ban]
  roles:       [admin, member, observer]
  governance:  single-admin
  memory_scope: full
  ttl:         optional
  tools:       none
  metadata_visibility: { member_count: PreJoin, context_age: MemberOnly, creator_identity: PreJoin, name: PreJoin, description: PreJoin, economic_policy: MemberOnly, outlet_interface_count: MemberOnly, child_context_info: MemberOnly }

Template: "scp:template/public-broadcast"
  mode:          Broadcast
  ceiling:       [messages:read, messages:write, outlet:register, outlet:query:*, outlet:call:*]
  roles:
    owner:       all capabilities in ceiling + member:invite, role:assign, context:close
    author:      messages:write, messages:read, outlet:query:*, outlet:call:*
    subscriber:  messages:read (auto-granted on DID-authenticated registration)
  governance:    single-admin
  memory_scope:  full
  ttl:           optional
  metadata_visibility: all PreJoin
  projection_policy: { default_rule: Public, overrides: [] }

Template: "scp:template/gated-broadcast"
  mode:          Broadcast
  ceiling:       [messages:read, messages:write, outlet:register, outlet:query:*, outlet:call:*]
  roles:
    owner:       all capabilities in ceiling + member:invite, role:assign, context:close
    author:      messages:write, messages:read, outlet:query:*, outlet:call:*
    subscriber:  messages:read (requires admin-issued UCAN)
  governance:    single-admin
  memory_scope:  full
  ttl:           optional
  metadata_visibility: { member_count: MemberOnly, all others: PreJoin }
  projection_policy: { default_rule: Gated, overrides: [] }

Template: "scp:template/outlet-interface"
  ceiling:       [messages:read, messages:write, outlet:register, outlet:query:*, outlet:call:*, member:ban]
  roles:         [admin (creator), member (joiner)]
  governance:    single-admin
  memory_scope:  full
  ttl:           optional
  outlets:       creator-defined at creation
  metadata_visibility: all PreJoin

Template: "scp:template/paid-service"
  ceiling:       [messages:read, messages:write, outlet:register, outlet:query:*, outlet:call:*, member:ban]
  ceiling_policy: immutable
  roles:         [admin (creator), member (joiner)]
  governance:    single-admin
  memory_scope:  full (receipts are provenance)
  economic_policy: required — per_outlet_call must be set at creation
  extends:       scp:template/outlet-interface
  ttl:           optional
  metadata_visibility: { economic_policy: PreJoin, member_count: MemberOnly, all others: PreJoin }

Template: "scp:template/paid-broadcast"
  mode:          Broadcast
  ceiling:       [messages:read, messages:write]
  ceiling_policy: immutable
  roles:
    owner:       all capabilities in ceiling + member:invite, role:assign, context:close
    author:      messages:write, messages:read
    subscriber:  messages:read (requires admin-issued UCAN, granted after payment verification)
  governance:    single-admin
  memory_scope:  full
  economic_policy: required — per_period must be set at creation
  extends:       scp:template/gated-broadcast
  ttl:           optional
  metadata_visibility: { member_count: MemberOnly, economic_policy: PreJoin, all others: PreJoin }
  projection_policy: { default_rule: Gated, overrides: [] }
```

The ONLY difference between `public-broadcast` and `gated-broadcast` is whether the subscriber role's `messages:read` is auto-granted (DID-authenticated, following the context reader-tier pattern §6.2.2B) or requires an explicit admin-issued UCAN (like encrypted context membership). The open/gated distinction is expressed through the template's role definitions, not through a new enum type.

Templates are not extensible by users — they are protocol constants. A template ID is a commitment: "this context has exactly these properties." If you need something a template doesn't cover, use explicit `ContextParams`. Templates and explicit params are equally valid; templates are just the fast path for common cases.

**Template in metadata.** When a context is created from a template, the template ID appears in context metadata (§5.7). This means the joining party sees `template: "scp:template/bilateral-ephemeral", ttl: 300s` instead of evaluating six independent parameters. Template-based evaluation is a single check: "do I accept this template from this DID at this TTL?"

### 5.12.2 Auto-Accept Policies

Agents MAY configure policies for automatic context acceptance — rules that allow the SDK to join contexts without human-in-the-loop confirmation. Auto-accept policies are local to the agent (never shared with the network) and evaluated entirely in the SDK.

Policy structure:

```
AutoAcceptPolicy {
  template:        TemplateID          // Which template(s) to auto-accept
  from:            TrustRequirement    // Who can trigger auto-accept
  max_ttl:         Duration?           // Maximum TTL to accept (optional cap)
  rate_limit:      Rate?               // Max auto-accepts per time window
}

TrustRequirement:
  | shared_context    // DID shares at least one active context with me
  | known_did(list)   // DID is in an explicit allowlist
  | discovery_context // DID is registered in a context with discovery tools I trust
```

Example policy: "Auto-accept `bilateral-ephemeral` contexts from any DID I share at least one context with, if TTL ≤ 10 minutes, at most 5 per hour."

**Security properties:**
- Policies never auto-accept contexts with outlet capabilities (ceiling containing `outlet:query:*` or `outlet:call:*`). Outlet access always requires explicit confirmation. This is non-overridable.
- Rate limiting prevents a compromised contact from flooding auto-accepts.
- The `shared_context` trust requirement means strangers can never trigger auto-accept — the existing shared context provides the trust baseline.
- Auto-accept policies are enforced in the SDK, not the protocol. The protocol sees a normal context join. The policy just determines whether the SDK prompts the human or acts autonomously.

**No auto-accept for outlet-bearing contexts.** This is a hard rule, not a default. Any context whose ceiling includes `outlet:query:*`, `outlet:query:{outlet_id}`, `outlet:call:*`, `outlet:call:{outlet_id}`, `outlet:register`, or any outlet-related capability requires explicit human or agent confirmation regardless of auto-accept policies. The rationale: outlet access is the capability that enables cross-context data flow (§6.2). Auto-accepting it would silently expand the agent's cross-context attack surface.

**No auto-accept for paid contexts.** This is a hard rule, not a default. Any context with an `EconomicPolicy` requiring payment (non-empty `CostSchedule`) requires explicit confirmation regardless of auto-accept policies. Agents never silently incur costs. See §19.3.

### 5.12.3 SDK Convenience Surface

The SDK provides template-based creation as the primary context creation path, with explicit `ContextParams` as the advanced path. Template-based creation is a single call that handles MLS group setup, sender key generation, event log initialization, and transport publishing internally.

```
// Primary path: template-based creation
sdk.create_context(
  template: "bilateral-ephemeral",
  peer: bob_did,                      // For bilateral templates
  ttl: Duration::minutes(5)
) → ContextHandle

// Equivalent explicit path (same result, more configuration)
sdk.create_context(params: ContextParams {
  ceiling: [messages:read, messages:write],
  roles: [admin, member],
  governance: SingleAdmin,
  memory_scope: Ephemeral,
  ttl: Duration::minutes(5),
  tools: [],
  template_id: None,                  // No template — custom params
}) → ContextHandle
```

**Bilateral shorthand.** For bilateral templates, the SDK accepts a peer DID directly and handles the invitation internally. The creator creates the context and immediately sends the invitation. If the peer has an auto-accept policy that matches, the join is automatic. If not, the peer's agent is prompted.

**Invitation bundling.** When creating a bilateral context with a peer, the SDK bundles the context metadata and MLS Welcome message into a single transport delivery. The peer receives everything needed to evaluate and join in one message — no roundtrip to fetch metadata before deciding.

#### 5.12.3.1 InvitationBundle Wire Format

The invitation bundle is the single-delivery package that enables zero-roundtrip context joining. It is serialized as MessagePack (§17.5) and encrypted to the invitee's public key (X25519, derived from their Ed25519 identity key via RFC 7748 birational mapping).

```
InvitationBundle {
  context_id:         String              // The context being invited to.
  creator_did:        DID                 // The DID of the context creator / inviter.
  relay_urls:         Vec<String>         // Relay endpoints where the context is hosted.
  welcome_message:    Vec<u8>             // MLS Welcome message (RFC 9420 §12.4.3.1).
                                          // Contains the GroupInfo, encrypted group secrets,
                                          // and the invitee's KeyPackage reference.
                                          // Omitted (empty) for Broadcast contexts.
  key_material:       InvitationKeyMaterial  // Context-specific key material for the invitee.
  metadata_snapshot:  MetadataSnapshot    // Snapshot of structural + visible operational metadata.
  signature:          Ed25519Signature    // Creator signs all fields above.
}

InvitationKeyMaterial {
  context_metadata_key:  [u8; 32]        // Symmetric key for metadata routing ID derivation (§9.10.4.B).
  sender_key_seed:       Option<Vec<u8>> // Initial sender key material (Broadcast contexts only).
}

MetadataSnapshot {
  structural:   StructuralMetadata       // Template ID, ceiling, roles, governance, TTL, etc.
  operational:  OperationalMetadata      // Member count, age, creator, name, description, etc.
                                         // Filtered by MetadataVisibilityPolicy — MemberOnly
                                         // fields are omitted for non-member invitees.
}
```

**Signature scope.** The creator signs `SHA-256("SCP-INVITATION-BUNDLE-V1:" || context_id || creator_did || relay_urls_hash || welcome_message_hash || key_material_hash || metadata_snapshot_hash)` where each `_hash` is `SHA-256(MessagePack(field))`. The signature uses the creator's Active Signing Key (`#active`).

**Validation.** The invitee verifies the bundle before processing:
1. Resolve `creator_did` and verify `signature` against the creator's `#active` public key.
2. Validate `metadata_snapshot.structural` against the invitee's auto-accept policy (§5.12.2).
3. If accepted, process `welcome_message` via MLS to join the group (Encrypted contexts) or initialize subscriber state (Broadcast contexts).
4. Use `context_metadata_key` to derive the metadata routing ID for ongoing metadata retrieval.

#### 5.12.3.2 JoinResponse Wire Format

After accepting an invitation bundle, the invitee sends a join response back to the creator via the relay. The response is serialized as MessagePack and encrypted to the creator's public key.

```
JoinResponse {
  context_id:       String              // The context being joined.
  joiner_did:       DID                 // The DID of the joining member.
  mls_commit:       Vec<u8>             // MLS Commit message confirming group join
                                        // (Encrypted contexts only; empty for Broadcast).
  sender_key:       Vec<u8>             // The joiner's initial sender key for this context
                                        // (§9.16). Encrypted to the context's current
                                        // sender key distribution mechanism.
  timestamp:        u64                 // Unix timestamp (seconds) of the join.
  signature:        Ed25519Signature    // Joiner signs all fields above with #active key.
}
```

**Signature scope.** The joiner signs `SHA-256("SCP-JOIN-RESPONSE-V1:" || context_id || joiner_did || mls_commit_hash || sender_key_hash || timestamp)`.

#### 5.12.3.3 Transport Delivery

Invitation bundles and join responses are delivered via the relay transport layer (§10.4, §10.5). Both messages use the same `OuterEnvelope` format as regular context messages:

1. **Invitation delivery.** The creator publishes the `InvitationBundle` to the invitee's personal routing ID (`SHA-256(len(invitee_did) || invitee_did || "scp-invitations")`, where `len()` is a 4-byte big-endian unsigned integer). The length prefix prevents boundary-shift attacks where a DID suffix could be confused with the domain separator. This is a reserved routing ID that every SCP identity subscribes to for receiving invitations.
2. **Join response delivery.** The joiner publishes the `JoinResponse` to the creator's personal routing ID, using the relay URLs from the invitation bundle.
3. **TTL.** Invitation bundles carry a relay TTL of 7 days (default). After expiry, the invitation must be re-sent. Join responses carry a TTL of 24 hours.
4. **Deduplication.** The `context_id` + `creator_did` + `joiner_did` triple uniquely identifies an invitation flow. Duplicate bundles (retransmissions) are idempotent — processing the same MLS Welcome twice produces the same group state.

### 5.12.4 Context Creation as a Runtime Operation

Context creation is not infrastructure provisioning. It is a runtime operation — comparable in weight to opening a TLS connection, not to deploying a database. Understanding this is critical to the protocol's viability: if context creation feels like a build action, agents will treat it as one and route around it for lightweight coordination. Context creation must be (and is) as fluid as `connect()`.

**Computational profile of context creation:**

```
Operation                              Time          Analogy
─────────────────────────────────────────────────────────────────
Template params lookup                 <1μs          HashMap::get()
MLS group init (2-member)              1-5ms         TLS handshake
Sender key generation (HKDF+Ed25519)   <1ms          Key derivation
Event log init (empty Merkle tree)     <1ms          Allocate a buffer
UCAN token minting (Ed25519 sign)      1-2ms         Sign a JWT
Pseudonym derivation (HMAC-SHA256)     <1ms          HMAC
State persistence (serialize+write)    1-5ms         Write to keychain
─────────────────────────────────────────────────────────────────
Total local computation                ~5-15ms
```

No disk provisioning. No schema migrations. No index building. No connection pooling. The local computation is a handful of key derivations and one signature. The real cost is network: delivering the invitation to the peer and receiving their join response.

**Network profile — first contact:**

```
Creator                        Relay                          Peer
   │                              │                              │
   ├─── create (local, ~10ms) ───►│                              │
   │                              │                              │
   ├─── invitation bundle ───────►├─── deliver to peer ─────────►│
   │    (metadata + MLS Welcome)  │                              │
   │                              │                              ├── evaluate
   │                              │                              │   (local, <1ms
   │                              │                              │    with template)
   │                              │                              │
   │                              │◄── MLS join + sender key ───┤
   │◄── relay forward ───────────┤                              │
   │                              │                              │
   ├── context Active ────────────┼──────────────────────────────┤
   │                              │                              │
   Total: ~10ms local + 2 relay hops (1 roundtrip with bundling)
   Wall clock: 100-500ms depending on transport latency.
   With auto-accept: no human delay. Fully autonomous.
```

With invitation bundling (§5.12.3), the peer receives metadata and MLS Welcome in one delivery. The peer evaluates the template, auto-accepts (or prompts), and joins — sending their MLS join response and sender key in one return delivery. Two relay hops total. With WebSocket transport to a shared relay, this is sub-200ms.

**Network profile — message in standing context (steady state):**

```
Sender                         Relay                          Receiver
   │                              │                              │
   ├── encrypt (local, <1ms) ────►│                              │
   ├── outer envelope ───────────►├── route to receiver ────────►│
   │                              │                              ├── decrypt
   │                              │                              │   (local, <1ms)
   │                              │                              │
   Total: 1 relay hop. Sub-50ms on WebSocket. Sub-100ms cross-relay.
```

Once a context exists, message exchange is one transport hop with sub-millisecond local crypto on each side. This is the steady-state performance for all contexts — standing or ephemeral.

### 5.12.5 Context Lifecycle in Application Architecture

Contexts are runtime objects. They are created, used, and destroyed during normal application operation — not provisioned ahead of time, not deployed as infrastructure. The SDK manages context lifecycle the same way a network library manages connections.

**Application startup:**

```
1. sdk.init(identity, storage, transport_config)
   ├── Load identity from secure storage
   ├── Load persisted context state (all Active contexts survive restart)
   ├── Reconnect transport for all Active contexts (background, non-blocking)
   └── Begin processing queued invitations

2. Standing contexts are immediately available.
   Messages sent before transport reconnects are queued locally.
   Messages received while offline are retrieved from relay on reconnect.
```

**During operation — contexts are created and destroyed fluidly:**

```
Agent lifecycle                              Context operations
──────────────────────────────────────────────────────────────────

Receives task: "coordinate with Bob"
  └── sdk.standing_context(bob_did)          [get-or-create, ~0ms or ~200ms]
      └── channel.send("sync on project?")   [send, 1 hop]

Receives task: "negotiate contract terms"
  └── sdk.create_context(                    [create, ~200ms]
        template: "bilateral-ephemeral",
        peer: vendor_did,
        ttl: 30.minutes)
      └── ctx.send(proposal)                 [send, 1 hop]
      └── ... negotiate ...
      └── [TTL expires, context auto-closes, keys destroyed]

Receives task: "start team discussion"
  └── sdk.create_context(                    [create, ~200ms]
        template: "group-discussion")
      └── ctx.add_member(alice_did)          [MLS add, 1 roundtrip]
      └── ctx.add_member(carol_did)          [MLS add, 1 roundtrip]
      └── ctx.send("kick off meeting")       [send, 1 hop]

Application shutdown:
  └── sdk.shutdown()
      ├── Persist all Active context state
      ├── Flush pending event log entries
      └── Close transport connections
      // Contexts survive. On next startup, they reconnect.
```

**Key property: contexts survive process restarts.** Context state (MLS group state, sender keys, event log position) is persisted to secure storage on every state transition (ADR-008). When the application restarts, all Active contexts are restored and transport is reconnected. No re-creation, no re-invitation, no re-negotiation. This is why standing contexts work — they persist across application sessions, device reboots, and network interruptions.

**Contexts are not connections.** A TCP connection dies when the process exits. A context does not. A context is a durable cryptographic group that happens to use connections for transport. The transport layer is replaceable (§8, ADR-012) and reconnectable. The context is the stable entity; the transport is ephemeral plumbing underneath.

### 5.12.6 The Contact Graph

Agents that coordinate regularly maintain **standing bilateral contexts** — the agent's contact graph. A standing context is a `bilateral-persistent` context with no TTL, created once and kept alive for the duration of the relationship.

**Lifecycle of a standing context:**

```
Relationship stage        Protocol action                Cost
──────────────────────────────────────────────────────────────────
First contact             create_context + invitation    ~200ms (one-time)
Ongoing communication     send/receive in context        <100ms per message
Idle period               nothing (context persists)     0 (no keepalive)
Reconnect after offline   transport reconnect            background, automatic
Relationship ends         close_context                  one-time, keys preserved or destroyed per memory scope
```

**Standing contexts have zero idle cost.** No keepalives, no heartbeats, no periodic key rotation (MLS key updates happen on message send, not on a timer). An agent with 500 standing contexts and no active conversations uses zero network bandwidth. The only cost is local storage for persisted MLS state — approximately 2-5KB per bilateral context (two-leaf ratchet tree, sender key material, minimal event log metadata).

**Standing contexts vs. ephemeral contexts — when to use which:**

| | Standing context | Ephemeral context |
|---|---|---|
| Template | `bilateral-persistent` | `bilateral-ephemeral` |
| TTL | None (lives indefinitely) | Required (forces intentionality) |
| Memory scope | Full (history preserved) | Ephemeral (keys destroyed on close) |
| Use case | Ongoing relationship, general communication | Bounded task, sensitive negotiation, time-boxed coordination |
| Analogy | Phone contact | Phone call |
| Creation | Once per relationship | Once per interaction |

An agent typically has a standing context with every peer it communicates with regularly, and creates ephemeral contexts on top of that for specific bounded tasks — especially tasks involving sensitive data that should not persist.

**First-contact optimization.** When two agents already share a context (e.g., both are members of a group), creating a standing context between them is faster: both agents already have each other's DID documents and MLS key packages cached from the shared context. The SDK SHOULD use this cached key material to skip DID resolution, reducing first-contact setup to a single relay roundtrip.

## 5.13 Context Nesting

Contexts can have parent-child relationships. A child context is a full context — its own MLS group, event log, governance, roles, tools, ceiling, and membership — that is structurally and cryptographically linked to one or more parent contexts. The parent relationship constrains the child (ceiling inheritance, lifecycle coupling, membership eligibility), is visible in metadata, and is bound into the child's MLS group identity so that lineage cannot be forged or rewritten after creation.

Nesting serves two distinct purposes depending on parent count:

- **Single-parent child** — a sub-space within a context. Per-task rooms, per-topic channels, per-match game instances. The parent contains the child; the child narrows the parent's scope.
- **Multi-parent child** — a governed bridge between contexts. A shared collaboration space where members from different parent contexts interact as peers. This is the protocol's structural mechanism for symmetric cross-context communication.

```
Single-parent (sub-space):              Multi-parent (bridge):

  Context A                               Context A ──┐
    │                                                  ├── Child C
    └── Child C                           Context B ──┘
        (sub-space of A)                      (bridge between A and B)


Multi-parent chain:

  Context A ──┐
              ├── Child C ──┐
  Context B ──┘             ├── Grandchild E
                Context D ──┘
```

### 5.13.1 Ceiling Inheritance

A child's capability ceiling is the intersection of all parent ceilings. This is enforced at creation time and is the hard security boundary that prevents capability escalation through nesting.

```
Parent A ceiling: [messages:read, messages:write, outlet:query:*, outlet:call:*, media]
Parent B ceiling: [messages:read, messages:write, outlet:query:*, outlet:call:*]

Child ceiling ≤ intersection = [messages:read, messages:write, outlet:query:*, outlet:call:*]
```

The child's ceiling can be equal to or narrower than the intersection — never broader. A child that only needs messaging can declare `[messages:read, messages:write]` even if the intersection would allow outlets.

If a parent has a `governed` ceiling policy (§5.3) and its ceiling is *reduced*, the child's ceiling is retrospectively reduced to maintain the intersection invariant. If this makes the child's ceiling empty (no capabilities remain), the child closes automatically. This cascade is logged in both the parent's and child's event logs. If a parent's ceiling is *expanded*, the child's ceiling does not automatically expand — the child's own ceiling policy governs.

### 5.13.2 Membership Eligibility

A member of a child context must be a member of **at least one** parent context. This is the eligibility pool — the set of identities that are permitted to join the child. The child's own governance (roles, admission requirements) determines who actually joins from that pool.

```
Parent A members: [Alice, Carol, Eve]
Parent B members: [Bob, Carol, Dave]

Eligible pool for child: [Alice, Bob, Carol, Dave, Eve]
  - Alice can join (via A)
  - Bob can join (via B)
  - Carol can join (via A or B — multi-anchored)
  - Dave can join (via B)
  - Eve can join (via A)
  - Frank cannot join (not in any parent)
```

**Eligibility is continuous, not one-time.** If a member is removed from their only active parent (i.e., the parent is still open but the member is individually removed from it), they lose eligibility in the child. The child's SDK detects the loss of eligibility and evicts the member — MLS remove_member, sender key rotation, event log entry. If the member is in multiple parents and loses one, they retain eligibility through the remaining parent(s).

**Enforcement mechanism.** Eligibility enforcement operates at two levels to prevent non-compliant SDKs from bypassing constraints:

1. **SDK-level validation.** The creating member's SDK validates eligibility at creation time — verifying that all proposed initial members belong to at least one parent context's membership roster. The SDK also monitors local membership state continuously: when local state reflects a membership loss in a parent, the SDK evaluates child eligibility and initiates eviction (MLS remove_member, sender key rotation, event log entry).

2. **Relay-level validation.** Relay infrastructure independently validates eligibility constraints on child context creation messages and membership addition messages. The relay verifies that (a) the child's declared ceiling is a subset of the intersection of all parent ceilings, and (b) each member being added is eligible through at least one parent context. Relay-side validation is independent of SDK behavior — a non-compliant SDK that attempts to create a child context violating parent ceiling constraints or add ineligible members will have its messages rejected by the relay. This makes eligibility enforcement a protocol-level guarantee, not an SDK honor system.

   **Eligibility verification by context mode.** The mechanism for verifying parent membership depends on the parent context's mode:

   - **Broadcast contexts.** The relay maintains plaintext membership rosters for broadcast contexts (no MLS encryption). The relay verifies membership directly by checking the parent's roster. No additional proof is required.

   - **Encrypted contexts.** The relay cannot read MLS group state, so membership rosters are opaque. Eligibility is proven via a **MembershipAttestation** — a signed statement from a parent context member who holds the `governance` capability:

     ```
     MembershipAttestation {
       parent_context_id: ContextId,      // The parent context attesting membership
       member_did: DID,                   // The member whose eligibility is attested
       attester_did: DID,                 // The governance-capable member signing this
       attested_at: u64,                  // Unix timestamp of attestation
       valid_until: u64,                  // Expiry (suggested: attested_at + 3600s)
       signature: Ed25519Signature,       // Attester's signature over the above fields
     }
     ```

     The child context creation request and membership addition messages include one `MembershipAttestation` per member per encrypted parent. The relay verifies: (1) the attester's DID is a known member of the parent context with `governance` capability (the relay tracks governance-capable members via context metadata updates), (2) the signature is valid, (3) `valid_until > now` (attestation is fresh), (4) `member_did` matches the member being added. Attestations are short-lived (default 1 hour) to limit replay risk.

     **Privacy consideration.** The attestation reveals to the relay that a specific DID is a member of the parent context. This is acceptable because the relay already knows context membership for routing purposes — the relay receives `SUBSCRIBE` messages per context and tracks which connections are associated with which contexts. The attestation adds no new information the relay doesn't already have.

     **Attestation flow.** When a member wants to create a child of an encrypted parent or add a member to such a child: (1) the member requests an attestation from a governance-capable member of the parent context (via the parent context's messaging channel), (2) the governance-capable member verifies the requester is indeed a parent member, signs and returns the attestation, (3) the requester includes the attestation in the child creation or member addition message to the relay.

**TOCTOU mitigation for eligibility checks.** A time-of-check-to-time-of-use race exists between SDK-side eligibility validation and relay-side validation: a member could be removed from their only parent between when the SDK checks eligibility and when the relay processes the child join message. The protocol mitigates this as follows:

1. **Relay checks are authoritative.** The relay validates eligibility at message processing time, not at SDK submission time. If the parent membership roster has changed between SDK check and relay processing, the relay's check reflects the current state. The relay's accept/reject decision is final.

2. **Eligibility proofs carry epoch binding.** When the SDK constructs a child context join or member-add message, the message includes an `eligibility_proof` containing the parent context ID(s) through which eligibility is claimed and the parent's current MLS epoch number (for Encrypted parents) or the parent's current membership sequence number (for Broadcast parents). This binds the eligibility claim to a specific point in the parent's membership state.

3. **Epoch staleness bound.** The relay MUST reject an eligibility proof if the parent's current epoch (or membership sequence) has advanced more than 2 epochs beyond the epoch cited in the proof. This bounds the TOCTOU window: if the parent's membership has changed significantly (more than 2 MLS commits) since the proof was generated, the proof is stale and the SDK must regenerate it with current parent state. The value of 2 allows for normal concurrent MLS commits (e.g., key updates by other members) without forcing unnecessary proof regeneration.

4. **In-flight MLS add rejection.** If the relay rejects an eligibility-bearing MLS add message, the MLS Commit containing the add is rejected entirely. The SDK receives an error and must re-evaluate eligibility before retrying. No partial MLS state change occurs — MLS Commits are atomic.

**Distinction from parent sever.** Individual member removal from an active parent triggers continuous eligibility enforcement. When a parent itself severs (closes or is disconnected), the outcome is governed by the `on_sever` configuration agreed upon at creation (§5.13.4), which may differ from the continuous eligibility default.

**Joining a child does not grant membership in any parent.** Bob joining child C (via eligibility through parent B) does not make Bob a member of parent A. Parent membership is independent. The child is a meeting point, not a gateway.

**Children do not confer eligibility for other children.** Membership in a child context does not make a member eligible for sibling children of the same parent, or for children of other parents. Eligibility flows downward (parent → child), never upward or sideways.

### 5.13.3 Creation

Child context creation requires governance approval from every parent context. The creator does not need to be in all parents — they need creation rights in one parent, and governance in each additional parent must independently approve.

**Creation scenarios:**

**A. Single creator with standing in multiple parents.** Alice is a member of both A and B. She has creation rights (via her role) in both. She creates child C with parents [A, B]. Both A and B's governance approve based on Alice's standing.

```
Alice (in A + B) → sdk.create_child_context(
  parents: [context_a, context_b],
  ceiling: [messages:read, messages:write],
  ttl: .hours(2)
)
→ A's governance approves (Alice has contextCreate capability in A)
→ B's governance approves (Alice has contextCreate capability in B)
→ Child C created
```

**B. Coordinated creation across contexts.** Alice is in A with creation rights. Bob is in B with creation rights. Neither is in the other's context. They coordinate (via a bilateral context, shared context, or out-of-band) to create child C.

Coordination uses an intrinsic tool call available within each context's governance. Alice invokes the child-creation tool in A with the proposed child params and the list of co-parents. A's governance evaluates and, if approved, publishes a **child creation proposal** — a signed, content-addressed record of the approved params. Bob does the same in B. The protocol matches proposals by their content hash: when all proposed parents have published matching proposals (identical child params), the child is created.

**Proposal format and matching algorithm:**

```
ChildCreationProposal {
    proposal_id:        UUID,                // Unique per proposal
    child_params:       ContextParams,       // Full child context parameters
    parent_context_ids: Vec<ContextId>,       // Sorted lexicographically — all proposed parents
    proposer_did:       DID,                  // The member who initiated in this parent
    parent_context_id:  ContextId,            // The parent publishing this proposal
    created_at:         u64,                  // Unix milliseconds
    expires_at:         u64,                  // Unix milliseconds (created_at + timeout)
    approval_signature: Ed25519Signature,     // Governance approval signature (admin #active key)
}

Matching hash (content-addressed):
    match_hash = SHA-256(
        canonical_msgpack(child_params) || sorted(parent_context_ids)
    )
```

Proposals from different parents match when their `match_hash` values are identical — meaning they propose the same child parameters for the same set of parents. The `child_params` are serialized in canonical MessagePack (sorted map keys, no optional field omission) to ensure deterministic hashing across independent serialization by different SDKs.

**Proposal publication.** Each approved proposal is published as a relay message to a coordination routing address derived from the match hash:

```
coordination_routing_id = SHA-256(match_hash || "scp-child-creation")
```

All parents' SDKs subscribe to this routing address. When an SDK observes proposals from all parents in the `parent_context_ids` list with the same `match_hash`, all proposals are matched and creation proceeds.

**Timeout.** Proposals expire after a configurable timeout. RECOMMENDED default: 5 minutes. The timeout is declared in the proposal (`expires_at`). If not all parents have published matching proposals before any proposal's `expires_at`, the coordination fails. Expired proposals are discarded — they cannot be matched against later proposals.

**Partial approval handling.** Coordination is all-or-nothing. If any parent's governance rejects the proposal, creation fails entirely. If some parents approve and others have not yet responded:

- Approved proposals are published and wait for matching.
- If the timeout elapses before all parents approve, all published proposals expire. No child is created.
- Expired proposals are logged in their respective parent's event log as `ChildCreationProposalExpired { match_hash, reason: .timeout }`.
- A new coordination attempt requires new governance proposals in all parents — expired approvals are not reusable.

```
Alice (in A) → invokes child creation tool → A's governance approves
             → A publishes proposal { match_hash, parent_list, approval_sig }
Bob (in B)   → invokes child creation tool → B's governance approves
             → B publishes proposal { match_hash, parent_list, approval_sig }
SDK observes matching proposals from all parents
→ Child C created
→ Both Alice and Bob are initial members
```

This reuses the existing tool call model — no new protocol primitive. The child creation tool is intrinsic to contexts that include the `context:child:createCreate` capability in their ceiling.

**C. Member proposal without creation rights.** Alice is in A but her role doesn't include creation rights. She proposes the child through A's governance (§5.9). A's governance evaluates and either approves or rejects the proposal. If approved, the governance itself authorizes the creation on A's behalf. Same process on B's side.

**Creation protocol:**

1. **Initiator constructs child params:** ceiling (must be ≤ intersection of parent ceilings), governance model, roles, TTL (must be ≤ minimum parent TTL if parents have TTLs), memory scope, tools, and the parent governance configuration (§5.13.4).
2. **Governance proposal sent to each parent.** The proposal includes the full child params plus the list of all proposed parents. Each parent's governance evaluates independently.
3. **All parents approve.** The child context is created. Creation is logged in every parent's event log and in the child's event log.
4. **Any parent rejects.** Creation fails. No child is created. The rejection is not logged (the proposal never materialized).

**Cryptographic binding.** When the child's MLS group is initialized (step 3), the parent context IDs and the content hash of the parent governance configuration are included in the MLS `group_context` extensions field. This makes the parent lineage part of the child's cryptographic group identity — the `group_id` derived from the `group_context` is a function of the parent references. Consequences:

- **Lineage is unforgeable.** Claiming different parents after creation would require creating a new MLS group with a different `group_id`. Any member can verify the parent lineage by inspecting the `group_context` extensions — no trust in metadata required.
- **Two independent verification paths.** The parent relationship is recorded in both the MLS `group_context` (cryptographic, part of the group identity) and the event log (Merkle tree, signed entries). Both would need to be compromised to forge lineage.
- **Governance config is tamper-evident.** The content hash of the `ParentGovernanceConfig` in the `group_context` means any discrepancy between the claimed governance configuration and the cryptographically committed one is detectable.

**MLS group_context extension format.** SCP defines a custom MLS extension for carrying context parameters in the `group_context`. The extension uses the IANA private-use range for MLS extension types:

```
Extension Type ID: 0xFF01 (SCP Context Parameters)

ExtensionType: 0xFF01
ExtensionData: MessagePack-serialized ScpContextExtension

ScpContextExtension {
    context_id:               ContextId,           // The SCP context ID
    context_mode:             u8,                   // 0 = Encrypted, 1 = Broadcast
    governance_policy_hash:   [u8; 32],            // SHA-256 of canonical_msgpack(governance_policy)
    ceiling_policy:           u8,                   // 0 = Immutable, 1 = Governed
    ceiling_hash:             [u8; 32],            // SHA-256 of canonical_msgpack(capability_ceiling)
    parent_context_ids:       Vec<ContextId>,       // Sorted lexicographically; empty for root contexts
    parent_governance_hash:   Option<[u8; 32]>,    // SHA-256 of canonical_msgpack(parent_governance_configs); None for root contexts
}
```

**Serialization.** The `ScpContextExtension` is serialized using canonical MessagePack (sorted map keys, deterministic encoding), matching SCP's standard serialization format (§17). This ensures that independent implementations produce identical byte representations for the same extension contents.

**Extension type ID.** `0xFF01` is in the IANA private-use range for MLS extension types (`0xFF00`-`0xFFFF`), as defined in RFC 9420 Section 17.3. If SCP registers with IANA in the future, the extension type ID will transition to an assigned value. SDKs MUST accept both the private-use ID and any future assigned ID during a transition period.

**Validation rules:**

1. The `ScpContextExtension` with type ID `0xFF01` MUST be present in the `group_context.extensions` of every SCP MLS group. MLS groups without this extension are not SCP contexts and MUST be rejected.
2. The `context_id` in the extension MUST match the context ID in the context's metadata and event log.
3. The `governance_policy_hash` MUST match `SHA-256(canonical_msgpack(governance_policy))` computed from the context's declared governance policy.
4. The `ceiling_hash` MUST match `SHA-256(canonical_msgpack(capability_ceiling))` computed from the context's declared capability ceiling.
5. For child contexts: `parent_context_ids` MUST be non-empty and sorted lexicographically. `parent_governance_hash` MUST be present and match `SHA-256(canonical_msgpack(parent_governance_configs))`.
6. For root contexts: `parent_context_ids` MUST be empty. `parent_governance_hash` MUST be `None`.
7. Any mismatch between the extension contents and the context's metadata is a protocol violation. The SDK MUST reject the MLS group and report the discrepancy.

**Parent awareness.** When Context A's governance receives a child creation proposal that includes Context B as a co-parent, A's governance sees B's context metadata (§5.7) — ceiling, member count, governance model, age, etc. This is the same metadata visible to anyone inspecting a context before joining. A's governance can evaluate whether a relationship with B is acceptable based on this metadata.

### 5.13.4 Parent Governance Configuration

The governance relationship between parents and child is configurable at creation time — not prescribed by the protocol. The creators (with parent governance approval) configure a set of parent governance permissions that define what authority each parent retains over the child after creation.

**Configurable permissions (per parent):**

```
ParentGovernanceConfig {
  can_close_child:       Bool    // Can this parent unilaterally close the child?
  can_evict_members:     Bool    // Can this parent evict members from the child?
  can_restrict_ceiling:  Bool    // Can this parent further restrict the child's ceiling?
  requires_approval_for: [       // What child operations require this parent's approval?
    | governanceChange           // Child governance model changes
    | toolRegistration           // New tools added to child
    | ceilingChange              // Child ceiling modifications (only applicable if child has `governed` ceiling policy, §5.3)
    | membershipChange           // Members added/removed
  ]
  on_sever: .evict_unique_members  // When this parent severs: evict members eligible only through this parent
          | .cascade_close          // When this parent severs: close the child entirely
          | .preserve_membership    // When this parent severs: child continues, current members retain membership
                                    // (members lose their eligibility anchor but keep their seat — a deliberate
                                    // governance choice to prioritize continuity over strict eligibility enforcement)
}
```

**Both parents agree on EACH OTHER'S configuration at creation time.** This is mutual consent — A sees what governance authority B will have over the child, and vice versa. The configuration is visible in the child's metadata (§5.7) so members can evaluate the governance structure before joining.

**Examples of common configurations:**

**Symmetric collaboration** (two teams working together):
```
Parent A config: { can_close: false, can_evict: false, can_restrict: false,
                   requires_approval_for: [], on_sever: .evict_unique_members }
Parent B config: { same as A }
// Neither parent can unilaterally control the child. Severing removes that
// parent's unique members. The child governs itself within the ceiling.
```

**Durable joint venture** (relationship outlives either parent):
```
Parent A config: { can_close: false, can_evict: false, can_restrict: false,
                   requires_approval_for: [], on_sever: .preserve_membership }
Parent B config: { same as A }
// If either parent closes, the child continues with all current members.
// Members who were eligible only through the severed parent keep their seat.
// The child's own governance takes over fully. Use when the child's work
// should survive parent reorganization.
```

**Service relationship** (B provides a service to A's members):
```
Parent A config: { can_close: true, can_evict: false, can_restrict: false,
                   requires_approval_for: [], on_sever: .cascade_close }
Parent B config: { can_close: false, can_evict: false, can_restrict: true,
                   requires_approval_for: [toolRegistration], on_sever: .cascade_close }
// A can shut down the relationship. B controls the tools (it's the service provider).
// If either severs, the child closes entirely.
```

**Supervised sub-space** (single-parent nesting):
```
Parent A config: { can_close: true, can_evict: true, can_restrict: true,
                   requires_approval_for: [governanceChange, ceilingChange],
                   on_sever: .cascade_close }
// Full parental authority. The child is a room within A.
```

**The parent governance configuration is immutable after creation.** Changing it would require creating a new child with different configuration. This prevents governance bait-and-switch — members join the child knowing exactly what authority each parent has, and that doesn't change.

### 5.13.5 Lifecycle Coupling

**Children cannot outlive all parents. No orphans.**

- When a parent context closes (manually or via TTL expiry), the parent-child relationship severs. The `on_sever` action configured for that parent executes.
- If the last parent closes, the child closes regardless of `on_sever` configuration. A child with no parents has no trust anchors and no structural governance authority. It closes. Even `.preserve_membership` cannot prevent this — the option preserves membership through individual parent severances, not through the loss of all parents.
- Children can close independently without affecting any parent. A child closing is logged in every parent's event log.

**TTL inheritance.** A child's TTL cannot exceed the minimum TTL of its parents (among parents that have TTLs). If parent A has TTL = 1 hour and parent B has no TTL, the child's TTL is bounded by 1 hour. If neither parent has a TTL, the child's TTL is unconstrained.

Rationale: TTL is part of the opt-in contract (§5.10). Parent A's members consented to a 1-hour interaction. A child that outlives A would extend the interaction's footprint beyond what A's members expected. Bounding the child's TTL by the parent's prevents this.

**Lifecycle event log entries:**

```
In parent's event log:
  ChildCreated { child_id, co_parents: [contextID], creator: DID, ceiling, config }
  ChildClosed  { child_id, reason: .manual | .ttl_expiry | .parent_sever | .orphaned }

In child's event log:
  Created           { parents: [contextID], ceiling, config }
  ParentSevered     { parent_id, reason: .closed | .manual_sever, action: on_sever }
  MemberEvicted     { did, reason: .parent_sever(parent_id) }
  ClosedByOrphan    { last_parent_id }
```

### 5.13.6 Metadata and Legibility

Child context metadata (§5.7) includes all standard context metadata plus:

- **Parent context IDs.** The full list of parent contexts.
- **Parent metadata summaries.** For each parent: ceiling, governance model, member count, age. Enough to evaluate the trust basis without joining the parent.
- **Parent governance configuration.** What authority each parent has over the child (§5.13.4).
- **Eligibility basis.** Which parent(s) the prospective member would join through.

This means a member evaluating whether to join a child sees: "This is a child of contexts A and B. A has 30 members, single-admin governance, ceiling [msg, tools]. B has 15 members, multi-sig governance, ceiling [msg]. The child's ceiling is [msg]. Parent A can close the child unilaterally. Parent B cannot. If A severs, members from A only are evicted."

Full legibility before opt-in applies to nesting relationships the same as everything else in the protocol. No hidden parent governance. No undisclosed co-parents.

### 5.13.7 Interaction with Other Mechanisms

**Templates.** Well-known templates (§5.12.1) can be used for child contexts. The template constrains the child's params as usual; the parent relationship adds the ceiling intersection and lifecycle coupling on top. A child created from `bilateral-ephemeral` with two parents is an ephemeral bridge — TTL'd, keys destroyed on close, ceiling ≤ intersection.

**Standing contexts.** A standing context (§5.12.6) between Alice and Bob can be modeled as a multi-parent child of whatever context(s) Alice and Bob share. This is not required — standing contexts remain lightweight bilateral contexts that work without nesting. But if structural governance over the standing context is desired (a parent context's governance should have authority over the channel), nesting provides that.

**Tool interfaces.** Tool interfaces (§6.2) and multi-parent children serve different purposes and coexist:

| | Tool interface | Multi-parent child |
|---|---|---|
| Relationship | Asymmetric (caller/tool) | Symmetric (peers) |
| Data flow | Structured (schema-declared) | Full context (messages, tools, everything) |
| Governance | Both contexts govern each call | Configured at creation, child self-governs |
| Duration | Per-call (or per-session) | Persistent (until closed or TTL) |
| Use case | Service calls, data queries | Collaboration, negotiation, ongoing peer interaction |

A context might use both: tool interfaces for structured service queries and a multi-parent child for ongoing collaboration with the same counterpart.

**Provenance.** Data originating in a child context carries provenance (§7.7) that includes the child's parent lineage. When data from a child crosses another context boundary (via tool interface or further nesting), the provenance chain includes the child and its parents. This makes the trust basis structurally legible: "this data came from a child of A and B" tells the receiver more than "this data came from some context."

**Auto-accept policies.** Auto-accept policies (§5.12.2) can be extended to cover child context invitations. A policy might specify: "auto-accept invitations to children of contexts I'm already in, with ceiling ≤ [messages:read, messages:write], TTL ≤ 10 minutes." The parent lineage provides a stronger trust signal than a standalone context invitation — the member knows the child is governed by contexts they already participate in.

**Mixed-mode nesting.** A child context may have a different `ContextMode` than its parents. A Broadcast child of Encrypted parents enables public read access to curated content from a private group. An Encrypted child of Broadcast parents enables private discussion among subscribers. Ceiling inheritance (§5.13.1) and eligibility enforcement (§5.13.2) operate identically regardless of mode — they are structural properties, not encryption properties. The child's mode is declared at creation and visible in metadata.

### 5.13.8 Nesting Depth

Context-configurable via `ContextParams::max_nesting_depth`. Unbounded by default; contexts MAY set a limit. When set, the limit applies to the longest path from any root ancestor to the context being created. Nesting depth is immutable after context creation.

Deep nesting increases:

- Governance complexity (each level adds configurable permissions)
- Ceiling reduction (each level can only narrow, so deep nesting converges on empty ceilings)
- Lifecycle cascade depth (closing a grandparent cascades through children and grandchildren)
- Trust evaluation complexity (provenance with deep nesting lineage is harder to evaluate)

These costs are borne by context participants, not the protocol. Contexts that need deep hierarchies (organizational structures, layered communities) set `max_nesting_depth: None` (the default). Contexts wanting to bound complexity set an explicit limit (e.g., `Some(3)` for the previous behavior). See ADR-043.

## 5.14 Broadcast Contexts

Broadcast contexts (`ContextMode::Broadcast`) provide a feed/broadcast pattern for one-to-many communication at unlimited subscriber scale. Authors publish broadcast-key-encrypted content; subscribers request author keys and decrypt locally. No MLS group is required — the protocol substitutes per-author AES-256 broadcast keys with a pull-based distribution protocol identical to the one used for sender keys in encrypted contexts (§9.16.2).

### 5.14.1 ContextMode

```rust
pub enum ContextMode {
    Encrypted,  // MLS-backed, sender-side keys, full forward secrecy (default)
    Broadcast,  // Per-author broadcast keys, no MLS, mandatory subscriber registration
}
```

Added to `ContextParams`. Immutable after creation. Encrypted is the default for all contexts that do not explicitly specify a mode.

### 5.14.2 Author Broadcast Keys

Each author holds an AES-256-GCM broadcast key with a monotonic epoch counter. The mechanism is identical to encrypted-context sender keys (§9.16), but without MLS underneath — key distribution uses the same pull-based protocol over plain relay messages instead of MLS application messages.

**Broadcast key cohesion invariant:** An author's broadcast key is intrinsic to the broadcast context — created when the author role is granted, used exclusively within that context, and destroyed when the context closes or the author is removed. A broadcast context without its author keys is not a valid state. Implementations MUST NOT store broadcast keys separately from the broadcast context state; they are created together, used together, and destroyed together. Separating them creates orphaned keys or keyless contexts, both of which are security-relevant defects.

**Key lifecycle:**

1. Author generates initial broadcast key (epoch 0) on role grant.
2. Normal operation: encrypt content with current key.
3. On block: increment epoch, generate new key, publish `KeyEpochAdvance` notification.
4. Subscriber requests new key → author checks block list → responds with HPKE-sealed key or ignores.
5. On unblock: author can redistribute key to previously blocked DID on their next request.

**Key derivation:** New keys on rotation are freshly generated random 32-byte AES-256 keys (not HKDF-derived from a master secret). This provides key independence — compromise of one epoch's key reveals nothing about other epochs.

**HPKE parameters for broadcast key distribution.** Broadcast key distribution uses HPKE Base mode (RFC 9180) with the same suite as sender key distribution (§9.16.2): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. The `info` and `aad` parameters use a distinct domain separator:

```
info = "scp-broadcast-key-v1" || context_id || author_did || epoch_bytes
aad  = context_id || author_did || epoch_bytes
```

Where `context_id` and `author_did` are UTF-8 bytes and `epoch_bytes` is the 8-byte big-endian encoding of the broadcast key epoch. The `"scp-broadcast-key-v1"` domain separator is distinct from `"scp-sender-key-v1"` (encrypted contexts) and `"scp-access-key-v1"` (content access keys), preventing cross-protocol key confusion. The three domain separators ensure that an HPKE ciphertext produced in one protocol cannot be replayed in another — different `info` values produce different HPKE key schedules.

### 5.14.3 Subscriber Registration

Broadcast contexts reuse the two-tier membership model from contexts with discovery tools (§6.2.2B):

- **Writer tier (authors):** Hold `messages:write` UCAN. Bounded. Manage content and key distribution.
- **Reader tier (subscribers):** DID-authenticated (open) or UCAN-authenticated (gated). Unbounded. Receive author broadcast keys on request.

Subscribers register via DID-signed requests — the same pattern context readers use:

```rust
pub struct SubscriberRegistration {
    pub subscriber_did: DID,
    pub wrapping_pubkey: X25519PublicKey,
    pub ucan: Option<UcanToken>,   // Required for gated contexts (messages:read UCAN)
    pub timestamp: u64,
    pub signature: Ed25519Signature,
}
```

- Published to the context's `routing_id` as a structured relay message.
- Author SDKs process registrations, respond with current broadcast key via the pull-based key protocol.
- Event log records registration via `MemberJoined` with role `subscriber`.

### 5.14.4 Open vs. Gated Broadcast

The distinction between open and gated broadcast is expressed through the existing role/UCAN system at the template level, not through a new enum:

**Open broadcast** (`public-broadcast` template): The subscriber role's `messages:read` capability is granted on DID-authenticated registration — no admin-issued UCAN required. This mirrors context readers who query via DID-signed requests without UCAN.

**Gated broadcast** (`gated-broadcast` template): The subscriber role requires an explicit `messages:read` UCAN from the context admin. Same as encrypted context membership — capabilities require admin-issued tokens.

**Key request validation:**
- Open: author checks block list only. Not blocked → respond with key.
- Gated: author checks (1) valid `messages:read` UCAN, (2) block list. Both pass → respond with key.

Gated contexts enable: paid subscriptions (admin grants `messages:read` after payment verification — see §19.10 `paid-broadcast` template), invite-only communities (admin grants `messages:read` to approved members), and tiered access (scoped UCANs for different content levels).

The open/gated distinction governs all access paths to context content, not just key distribution. This includes HTTP broadcast projection (§18.11) — gated contexts require UCAN authentication on projection endpoints; open contexts serve publicly. The `ProjectionPolicy` on `ContextParams` provides per-author granularity within the bounds set by the admission mode. See §18.11.2.1 for the full projection policy specification.

### 5.14.5 BroadcastEnvelope

```rust
pub struct BroadcastEnvelope {
    pub version: u16,                   // Protocol version (§13.2.2). SCP/1.0 = 0x0100
    pub context_id: ContextId,
    pub author_did: DID,
    pub sequence: u64,
    pub key_epoch: u64,
    pub timestamp: u64,
    pub nonce: [u8; 12],                // AES-256-GCM nonce (random 12 bytes per message)
    pub encrypted_content: Vec<u8>,     // AES-256-GCM ciphertext || auth_tag
    pub provenance: Option<DataProvenance>,
    pub signature: Ed25519Signature,
}
```

**No `content_hash` field.** Content integrity is provided by the AES-256-GCM authentication tag. A cleartext `content_hash` would create a confirmation oracle for low-entropy messages (ADR-038). Omitting it from the signature also enables pre-decryption signature verification — receivers can reject forgeries without touching key material.

**Nonce generation.** The `nonce` field is a random 12-byte value generated via `OsRng` (CSPRNG) per message. Each invocation of `seal_broadcast` generates a fresh nonce. The nonce is a top-level field (not embedded in `content`) so that it participates in the signature and is authenticated independently of AEAD verification. Random nonces are safe because: (1) each broadcast key encrypts at most 2^32 messages before rotation (key epoch advance on block events), well below the 2^48 birthday bound for AES-256-GCM with 96-bit random nonces; (2) no state synchronization is required between sender and receiver; (3) the construction matches the sender key layer (§9.16.1) and the WrappedContent nonce (§9.17.3).

**AES-256-GCM additional authenticated data (AAD).** Content encryption in broadcast envelopes MUST bind the cleartext metadata fields as AAD:

```
aad = context_id || author_did || key_epoch_bytes || sequence_bytes
```

Where `context_id` and `author_did` are UTF-8 bytes (4-byte BE length prefix + bytes), `key_epoch_bytes` is 8-byte big-endian, and `sequence_bytes` is 8-byte big-endian. This prevents attribution forgery, epoch substitution, and message reordering by context members who possess the broadcast key. Tampering with any cleartext metadata field causes AEAD tag verification to fail on decryption.

**Signature formula:**
```
Ed25519_sign(active_signing_key_or_agent_signing_key, SHA-256(
    "SCP-BROADCAST-ENVELOPE-V1:" || version || len(context_id) || context_id || len(author_did) || author_did || sequence || key_epoch || timestamp || nonce || provenance_hash
))
```

Where:
- `provenance_hash = SHA256(serialize(provenance))` if present, or `SHA256(0x00)` if absent (same sentinel as InnerEnvelope, ADR-002).
- Variable-length fields (`context_id`, `author_did`) are 4-byte big-endian length-prefixed.
- `version` is 2 bytes big-endian.
- `sequence`, `key_epoch`, `timestamp` are 8 bytes big-endian.
- `nonce` is 12 bytes raw (fixed-size, no length prefix).
- `provenance_hash` is 32 bytes raw.

The domain separator `"SCP-BROADCAST-ENVELOPE-V1:"` prevents cross-protocol payload confusion. The nonce MUST be included in the signature to bind it to the specific encryption operation — without it, any broadcast key holder could re-encrypt different content under a new nonce while reusing the original author's valid signature.

**Send path:** validate UCAN (`messages:write`) → assign sequence number → generate random 12-byte nonce → hash provenance → sign (domain-separated hash of version, context_id, author_did, sequence, key_epoch, timestamp, nonce, provenance_hash) → AES-256-GCM encrypt plaintext with author broadcast key using nonce and AAD → serialize BroadcastEnvelope (cleartext metadata + encrypted payload) → wrap in OuterEnvelope → relay PUBLISH.

**Receive path:** transport receive → dedup by blob hash → deserialize → verify signature against author's Active Signing Key or Agent Signing Key from sender's DID document (pre-decryption rejection of forgeries) → decrypt with cached author broadcast key for this epoch using envelope nonce and reconstructed AAD → verify author UCAN → replay check (sequence number) → deliver to application layer.

**No `content_hash` in envelope or signature.** The BroadcastEnvelope does not contain a `content_hash` field, and `content_hash` is not part of the signature formula. Content integrity is provided by the AES-256-GCM authentication tag — a separate `content_hash` is redundant. More importantly, omitting `content_hash` from the signature enables **pre-decryption signature verification**: receivers can reject forged envelopes without accessing the broadcast key, since the signature covers only cleartext metadata fields. Placing a plaintext hash alongside ciphertext would also create a confirmation oracle for low-entropy messages (ADR-038). The cleartext BroadcastEnvelope contains only: `version`, `context_id`, `author_did`, `sequence`, `key_epoch`, `timestamp`, `nonce`, `encrypted_content`, `provenance`, and `signature`.

### 5.14.6 Routing

`routing_id = SHA-256(context_id)` — publicly derivable. Subscribers can subscribe to the relay topic, but cannot read content without author broadcast keys. This differs from encrypted context routing where `routing_id` is derived via HKDF from identity key material (§9.10.4) — broadcast contexts use a public derivation because author identity is visible in the BroadcastEnvelope (not hidden inside MLS encryption).

### 5.14.7 Membership

| Role | UCAN | Registered | Write | Read |
|---|---|---|---|---|
| Owner | Yes (full) | Yes | Yes | Yes |
| Author | Yes (`messages:write`) | Yes | Yes | Yes |
| Subscriber (open) | No (DID-auth only) | Yes (DID + wrapping key) | No | Yes |
| Subscriber (gated) | Yes (`messages:read`) | Yes (DID + wrapping key + UCAN) | No | Yes |

### 5.14.8 Blocking

Author-level, cryptographic, pull-based — the same protocol as encrypted contexts (§9.16.3):

1. Author adds DID to block list, increments key epoch.
2. Publishes `KeyEpochAdvance` notification (relay message, not MLS).
3. Blocked subscriber requests new key → no response → cannot decrypt future content.
4. Non-blocked subscribers request → get HPKE-encrypted key → continue reading.

Blocking is per-author. Author A blocking a subscriber does not affect the subscriber's access to Author B's content.

**Governance-level subscriber ban.** When the context's capability ceiling includes `member:ban` (§5.3), governance can execute `RevokeAccess { did, access: Read }` (§5.9, ADR-031) against broadcast subscribers. Unlike per-author blocking (which is unilateral and affects only one author's content), a governance ban removes the subscriber from the registry AND adds them to ALL authors' block lists simultaneously. All authors MUST rotate keys after a governance ban (mandatory `KeyEpochAdvance`). This mirrors `RevokeAccess` semantics in encrypted contexts (MLS group removal), adapted for broadcast's per-author key model.

Governance ban lifecycle:

1. Governance proposal: `RevokeAccess { did, access: Read }` — proposed via the standard governance flow (§5.9).
2. Context manager verifies `member:ban` capability in ceiling — rejects with `PermissionDenied` if absent.
3. On approval: subscriber removed from registry, added to all authors' block lists.
4. All authors rotate keys — mandatory `KeyEpochAdvance` per author.
5. `ReadAccessRevoked` event emitted to event log.
6. Future `handle_key_request` from banned subscriber returns `Deny` for all authors.

`RestoreAccess { did, capabilities }` reverses the ban: subscriber removed from all authors' block lists, but NOT re-registered (they must re-register manually). No key rotation on restore (forward-only — unban grants future access, the registration gap is permanent). `ReadAccessRestored` event emitted.

Default template configuration: encrypted templates include `member:ban` in their ceiling by default (§5.12.1); broadcast templates do not. Broadcast contexts can add `member:ban` via explicit `ContextParams` at creation or via `ModifyCeiling` governance action if `CeilingPolicy::Governed`.

**Author removal.** Removing an author from a broadcast context (revoking their broadcast key and preventing future publishing) is a governance-gated action. Author removal uses `GovernanceAction::RevokeAccess { did, access: Write }` — the general content access revocation mechanism (§5.9, ADR-031). `RevokeAccess` with `access: Both` stops publishing AND suppresses historical content; `access: Write` stops future publishing only. There is no standalone API to remove an author without governance approval. This enforces the protocol tenet: "Agents are participants, not enforcers." When the governance proposal is approved and executed: the author's broadcast key is destroyed, `publish()` returns `PermissionDenied`, key requests for the author return `Deny`, and a `WriteAccessRevoked` event is emitted. Subscribers who cached the author's old key can still decrypt historical messages (unless `access: Both` was used, in which case access keys are also destroyed per §9.17).

**Sybil resistance.** Broadcast contexts are the primary target for Sybil block bypass because key requests travel as relay messages (not MLS application messages). The membership gate in `handle_sender_key_request` verifies that the requester is a registered subscriber before distributing keys. Identity-linked block expansion and group blocking further mitigate Sybil attacks. See §9.16.6 for the full mitigation specification.

### 5.14.9 Capabilities

No new capability variants. `messages:write` and `messages:read` apply to both Encrypted and Broadcast modes — the abstract capability to write/read in a context. `ContextMode` determines the processing pipeline.

### 5.14.9.1 Economic Policy in Broadcast Contexts

`EconomicPolicy` (§19.3) applies to broadcast contexts identically to encrypted contexts — it is a property of `ContextParams`, not of `ContextMode`. Authors pay per-message costs; subscribers pay access costs if the context uses a gated template. `SenderVelocity` (§19.7) anti-spam metrics apply per-author in broadcast mode (each author is an independent sender). The `paid-broadcast` template (§19.8) is the canonical example of economic policy applied to broadcast contexts.

### 5.14.10 Event Log

Reuses existing event types wherever possible. Only one genuinely new type:

- `MessageSent` — reused for broadcast (same event, mode determines semantics)
- `role:assigned` — reused for author grant (role: `author`) and subscriber registration (role: `subscriber`)
- `MemberJoined` — reused for subscriber registration
- `TokenRevoked` — reused for gated subscriber revocation
- **`WriteAccessRevoked { did, scope }`** — emitted when a governance-approved write access revocation executes (replaces the former AuthorBlocked event). The author's sender key is destroyed. scope indicates Full (retroactive) or FutureOnly. Distinct from `TokenRevoked` (which has different semantics: UCAN revocation).
- **`KeyEpochAdvance { sender_did, epoch }`** — NEW event type, shared across both Encrypted and Broadcast modes

`ConsistencyCheckpoint.epoch` becomes `Option<u64>` (`None` for broadcast contexts, which have no MLS epoch).

### 5.14.11 Discovery

Broadcast contexts are discoverable through four mechanisms:

1. **DID document service endpoint.** Authors MAY publish an `SCPBroadcastContext` service entry in their DID document with the context ID and relay URLs.
2. **Contexts with discovery tools.** Authors register broadcast contexts via `agent_register` in contexts with discovery tools (§6.2.2B), with metadata indicating the context mode.
3. **`.well-known/scp`.** Operators MAY list broadcast contexts in their `.well-known/scp` document (§18.3). Only broadcast context IDs may be listed — encrypted context IDs MUST NOT appear (§9.10 metadata privacy).
4. **Out-of-band URI.** The universal context URI format (§18.4) is used for sharing context references: `scp://context/<context_id_hex>?relay=<url>&mode=broadcast`. The legacy format `scp://broadcast/<context_id_hex>?relay=<url>` is accepted as an alias and normalized to the universal format.

### 5.14.12 Security Model Delta

Relative to Encrypted contexts, Broadcast contexts have the following security property changes:

**Retained:** Ed25519 authentication, content integrity (content_hash + signature), provenance, non-repudiation, UCAN authorization, event log, human accountability.

**Changed:** Confidentiality via per-author broadcast key (not MLS). No MLS `membership_tag` (authentication is signature-only). No MLS forward secrecy (mitigated by key epoch rotation on block events). Public `routing_id` (SHA-256 of context_id, not HKDF-derived). Author identity visible to relays in the outer envelope (authors are public figures in a broadcast context — this is a feature, not a leak).

See §9.5, §9.8, §9.9, and §9.10 for the full broadcast security analysis.
