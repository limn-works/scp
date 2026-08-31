# 5. Contexts

## 5.1 Definition

All interaction happens within contexts. There is no concept of off-context communication at the protocol level. A context is a bounded, governed space — a cryptographic entity with its own key material, event log (append-only Merkle tree), governance model, membership roster, and capability ceiling. Contexts operate in one of two modes: **Encrypted** (one MLS group per context, sender-side keys, full forward secrecy) or **Broadcast** (per-author broadcast keys, no MLS, mandatory subscriber registration). The mode is set at creation and is immutable. A group chat is a context. A collaborative quest is a context. A generated Discord alternative is a context. DMs are a two-party context. An entire app's backend is a context (or set of contexts).

**Contexts are spaces, not actors.** They do not initiate, do not act, and have no agency. They hold the rules, the keys, and the audit trail. Agents (always bound to humans, §4) do the acting within them. Outlets (§5.4) do the computing within them. The context itself is passive infrastructure.

**Contexts are runtime objects, not infrastructure to deploy.** Creating a context is a runtime operation (~5-15ms local computation, ~200ms wall clock with network — see §5.12.4). Contexts are created, used, and destroyed during normal application operation. They survive process restarts (state is persisted) but are created as fluidly as opening a connection.

**Contexts are where apps live.** What people experience as "an app" is a composite: a context (or set of contexts) + members + outlets + data (§8.1). Long-lived contexts with no TTL host persistent applications — games, workspaces, social platforms. Ephemeral contexts with TTL host bounded tasks. The context is the app's lifecycle boundary. Protocol state (membership, roles, trust) is portable and survives app death; app state is the app's concern (§8.3).

**Every context contains:** a capability ceiling (§5.3), roles with permission sets (§5.5), a governance model (§5.9), outlets (§5.4), an optional TTL (§5.10), a memory scope (§5.11), and transparent metadata visible before opt-in (§5.7). These are all declared at creation. Contexts may be created from well-known templates (§5.12) for common patterns or from explicit parameters. Contexts can have parent-child relationships (§5.13) for sub-spaces and governed cross-context bridges.

**Two protocol-level mechanisms allow information to cross context boundaries:** outlet interfaces (§6.2) for asymmetric, structured, request/response interactions, and multi-parent child contexts (§5.13) for symmetric collaboration. Both require governance consent from all involved contexts. Agent isolation is absolute — no agent instance spans contexts (§6.1).

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

The following is the complete enumeration of the **built-in** capability categories available for context ceiling declarations. These are the only built-in category strings. A ceiling array MAY also contain well-formed **custom** capabilities (§5.3.1.1, §7.2) defined outside this table. SDKs MUST reject any ceiling entry that is neither a recognized built-in category nor a well-formed custom capability at context creation time.

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

**Parameterized categories.** `outlet:query:{outlet_id}` and `outlet:call:{outlet_id}` are the parameterized categories — they restrict invocation to a specific outlet. `outlet:query:*` grants invocation of all registered Query outlets; `outlet:call:*` grants invocation of all registered Action outlets. An `outlet:query:*` wildcard ceiling entry **covers** all `outlet:query:{outlet_id}` capabilities; an `outlet:call:*` wildcard ceiling entry **covers** all `outlet:call:{outlet_id}` capabilities (wildcard coverage; distinct from the parsing rule in §5.3.1.1, under which no wildcard is ever inferred from a non-wildcard string). The two stems are independent: `outlet:query:*` does NOT grant any `outlet:call:*` capability, and vice versa (§5.4.2 classification, §6.2 amplification rule).

**Category validation.** At context creation, the SDK validates that every entry in the ceiling array is well-formed per the ceiling-entry grammar below (§5.3.1.1). Built-in categories are matched exactly (case-sensitive); custom capabilities are accepted only when well-formed. Any entry that is neither a recognized built-in category nor a well-formed custom capability causes creation to fail with `InvalidCeilingCategory` error. This prevents forward-compatibility issues where an old SDK creates a context with built-in categories it cannot enforce, and it forecloses ambiguous custom entries that would otherwise require silent interpretation.

#### 5.3.1.1 Ceiling-Entry Grammar

A ceiling entry is **exactly one** of the following well-formed shapes:

1. **A built-in category** — one of the strings in the §5.3.1 table, matched exactly and case-sensitively (including the parameterized `outlet:query:{outlet_id}` / `outlet:call:{outlet_id}` and the resource wildcards `outlet:query:*` / `outlet:call:*`).
2. **A custom capability** of the form `{resource}:{action}` (§7.2) — the entry contains **exactly one** colon, and both `{resource}` and `{action}` are non-empty **kebab-case tokens**: lowercase ASCII alphanumerics and hyphens, `[a-z0-9-]+` (this charset is defined here — §5.3.1.1 is the authoritative definition — and is consistent with the kebab-case naming convention for capability URIs in §7.3.4.1). Neither token may contain a colon (`:`), an asterisk (`*`), whitespace, or any other character outside the kebab-case charset.
3. **An explicit resource wildcard** of the form `{resource}:*` — grants every action under `{resource}`. Here `{resource}` is a non-empty kebab-case token (same `[a-z0-9-]+` charset, no `:`, no `*`, no whitespace) and the action segment is the **single literal `*`**. The `*` is permitted **only** as the entire action segment of a wildcard entry: an `*` appearing in the resource position (e.g. `*:read`), or as a substring of either token (e.g. `pay*ments`, `payments:wr*`), is malformed → `InvalidCeilingCategory`. A bare `*` or `*:*` therefore never names “all resources” — there is no resource wildcard.

There is **no implicit or silent wildcard.** A wildcard must be written explicitly as `:*`.

**No privileged-built-in collision.** A custom entry (shape 2 or shape 3 above) is valid only if it does not name a built-in capability under **any** spelling. A custom entry's string MUST NOT denote a built-in capability — neither a built-in's user-facing colon form (e.g. `outlet:query:*`, `outlet:call:*`, `outlet:call:{outlet_id}`, `bridging`, `messages:read`) nor its canonical UCAN form (e.g. `outlet_query:*`, `outlet_call:*`, `bridging:*`, `context_child:create`), including the parameterized `outlet_query:{outlet_id}` / `outlet_call:{outlet_id}` families for any concrete `outlet_id`. A custom entry that names a built-in under any spelling MUST be rejected at context creation with `InvalidCeilingCategory` (e.g. a custom whose string is `bridging:*` — which denotes the `bridging` built-in — is rejected). This is enforced by **canonical resolution**, not by a denylist of forbidden spellings: an entry is admitted as a custom only if resolving its string through the protocol's single canonical capability parser (`Capability::new`, defined in code at `crates/scp-protocol/src/context/roles.rs`) does **not** yield a built-in capability. Because that parser is the sole authority on which strings denote built-ins — recognizing every built-in in both colon and UCAN spelling, and the parameterized `outlet_query:{outlet_id}` / `outlet_call:{outlet_id}` families for any id — the rule is **closed by construction**: it covers every built-in spelling uniformly and extends automatically to any built-in added later, with no spelling enumeration to maintain. Resolution is applied at the point a custom is admitted, rather than testing only the entry's projected UCAN string, because the masquerade it prevents — a custom that is a distinct ceiling entry yet presents a built-in's privilege when the ceiling is consumed for capability minting — arises specifically from a `Capability` custom value (including one materialized directly from an untrusted, deserialized ceiling that never passed through the colon parser at create time). The clause is stated here as the authoritative, normative invariant so the validator can cite §5.3.1.1 and a custom capability can never masquerade as a privileged built-in.

**No built-in-resource wildcard shadow.** A custom **shape-3 wildcard** `{resource}:*` is additionally invalid when `{resource}` is the **resource token of any built-in capability** — i.e. the `{resource}` projection (the segment before the colon in a built-in's canonical UCAN form) of any built-in (e.g. `member`, `messages`, `media`, `outlet_query`, `outlet_call`, `role`, `governance`, `context`, `metadata`). This set is defined by the built-in capabilities themselves — the resource token of each built-in — and is **generated** from them, never a hand-maintained enumeration, so it extends automatically as built-ins are added and cannot drift from the actual built-in set. Canonical resolution alone does not catch this case: a string such as `member:*` does **not** resolve to a built-in (there is no `member:*` built-in — only `member:invite`, `member:remove`, `member:ban`), so `Capability::new("member:*")` keeps it a `Custom` and the no-collision rule above admits it. Yet because ceiling wildcard coverage treats a stored `{resource}:*` entry as covering **every** action under `{resource}`, an admitted `member:*` would silently grant the privileged built-in actions in that family (e.g. `member:ban`, which gates the governance `Revoke` action — see §7) when the ceiling is consumed for capability minting. Such a custom wildcard MUST therefore be rejected at validation with `InvalidCeilingCategory`. This is **closed by construction** over the built-in resource-token set (the same `{resource}` projection that ceiling wildcard coverage matches against), not a hardcoded denylist, so it extends automatically to any built-in added later — consistent with the "no silent wildcard / a custom can never present built-in privilege" invariant above. A custom **non-wildcard** action under a built-in resource (shape 2 — e.g. `member:promote`, `messages:archive`) remains **valid**: it grants only itself via exact match and never the built-in actions. A custom wildcard over a **non-built-in** resource (e.g. `payments:*`, `a-b-c:*`) likewise remains **valid**.

A **single-token custom with no action** (e.g. `payments` — no colon, no action segment) is **malformed** and MUST be rejected at context creation with `InvalidCeilingCategory`. It MUST NOT be silently interpreted as `payments:*` or any other capability — silent widening would defeat the legibility tenet (§5.7), under which members see the exact ceiling they opt into.

A custom ceiling entry contains **exactly one** colon (the separator between resource and action). An entry with no colon, or with more than one colon (e.g. `payments:read:write`), is malformed → `InvalidCeilingCategory`. (This single-colon rule is specific to ceiling entries; it is *not* the multi-segment parsing used for capability/delegation URIs elsewhere, e.g. §7.3.4.)

Ceiling-entry strings are subject to the same string sanitization as other context string fields (§9.1A): implementations MUST reject any entry containing control characters (U+0000–U+001F, U+007F–U+009F), HTML-special characters (`<`, `>`, `&`, `"`, `'`), or whitespace, and MUST reject any entry exceeding the 256-byte string length cap that applies to context string fields (per the §9.1A "String field validation" table in §5.9). Whitespace is never permitted inside the `{resource}` or `{action}` tokens — this already follows from the kebab-case charset above. Any other unrecognized or ill-formed string (empty resource, empty action, a token outside the kebab-case charset, a stray `*`, etc.) is likewise rejected with `InvalidCeilingCategory`.

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
  kind:             OutletKind,      // Query or Action. See §5.4.2. Absent = Action (fail-safe).
  name:             String,          // Human-readable name. Max 256 UTF-8 bytes.
  description:      String,          // Outlet description. Max 4096 UTF-8 bytes.
  operator_did:     DID,             // The identity accountable for this outlet.
  schema: {
    input:          JSONSchema,      // MCP-compatible JSON Schema for input. Max 64 KiB serialized.
    output:         JSONSchema,      // MCP-compatible JSON Schema for output. Max 64 KiB serialized.
  },
  implementation_hash: [u8; 32],    // SHA-256 of the outlet's implementation artifact (see below).
  test_vectors:     Vec<TestVector>, // Known input-output pairs. Min 0, max 100.
  cost:             Option<OutletCost>, // Per-invocation cost (§19.3). Query outlets: amount == 0.
  message_catalog:  Vec<MessageTemplate>, // Wire-time message catalog. ≤ 256 entries, each template
                                     // ≤ 1 KiB UTF-8. Covered by the V2 signature preimage via
                                     // `catalog_hash` (below).
  registered_at:    u64,             // Unix timestamp (seconds) of registration.
  signature:        Ed25519Signature, // Operator DID signs the V2 canonical digest below.
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
- `description_hash = SHA-256(description_utf8_bytes)` (32 bytes, fixed width). The `description` field is operator-authored prose displayed to prospective invokers; committing `description_hash` into the V2 preimage binds the prose to the registration signature so a silent operator edit to `description` produces a diffable registration event.
- `schema_hash = SHA-256(MessagePack(schema))` (32 bytes, fixed width).
- `implementation_hash` is 32 bytes, fixed width.
- `test_vectors_hash = SHA-256(MessagePack(test_vectors))` (32 bytes).
- `cost_hash = SHA-256(MessagePack(cost))` (32 bytes), or `SHA-256(0x00)` (32 bytes) if absent. The sentinel preserves fixed width.
- `catalog_hash = SHA-256(MessagePack(message_catalog))` (32 bytes, fixed width). `message_catalog` is the ordered `Vec<MessageTemplate>` defined above; MessagePack serialization of an empty vector produces a 1-byte value (`0x90`) so `catalog_hash` is always well-defined. Committing the catalog into the V2 preimage binds every operator-controlled string field at registration under the signature; the catalog is NOT covered by `schema_hash`, so a separate `catalog_hash` is required.
- `registered_at_be` is `registered_at` encoded as an 8-byte big-endian unsigned integer.

The `V2` suffix, the `kind_byte` inclusion, the mandatory length prefixes on every variable-length field, and the explicit `description_hash` + `catalog_hash` terms together constitute the break from the pre-rename `SCP-TOOL-REGISTRATION-V1` domain; pre-migration signatures are not honored. The length-prefix requirement closes the "split-shift" preimage-collision class that the unprefixed pre-rename concatenation admitted (where a suffix of `outlet_id` could be reinterpreted as a prefix of `name`).

### 5.4.2 Outlet Classification (Query vs Action)

Outlets declare their semantic class at registration time. Classification is structural, not advisory — the runtime enforces it. It is the basis of the capability split (§5.3.1): a Query outlet is invoked under the `outlet:query` / `outlet_query` capability family; an Action outlet under `outlet:call` / `outlet_call`.

**`OutletKind::Query`** — read-only, idempotent, cacheable in principle.

- **Structural floor at registration.** `cost == None || cost.amount == 0`. A Query outlet MUST NOT declare a positive per-invocation cost, and `cost.cost_formula` MUST be absent (a dynamic pricing formula on an idempotent read is not coherent). Declaring a positive cost or a pricing formula at registration is a validation failure (`OutletErrorClass::Protocol::QueryCostViolation`). Registrations that fail this check are rejected before they reach the event log.
- **ReadOnlyInvocation guard at invocation.** The runtime invokes Query outlets through a `ReadOnlyInvocation` handle that denies writes to context state (messages, roles, registry, event log, governance, economic ledgers). Any attempt by an executor to mutate through this handle returns `OutletErrorClass::Protocol::QueryViolation`.
- **Cacheability.** Query outlets are semantically cacheable (idempotent, invoker-independent result for fixed `(outlet_id, input, implementation_hash)`). A protocol-level shared cache is **deferred** (§5.4.3); every Query invocation currently executes live. The semantic property is stable — a future cache will not change what Query outlets are, only how the runtime exploits their properties.
- **Query-with-declared-cost is forbidden.** An outlet registered with cost amount `> 0` MUST be `Action`. Operators who want a paid read-only interface (e.g., a metered data lookup) declare it as `Action`. The protocol contract is: a Query invocation is never billed.
- **UCAN stem.** `outlet_query:{outlet_id}` or `outlet_query:*` (see §5.4.2.1 for parser semantics).
- **Chain depth (§6.2).** Query cross-context calls use the full `ContextParams::max_chain_depth` budget (default 8, range [1, 255]).

**`OutletKind::Action`** — may mutate, never cached.

- No structural cost floor; Action outlets may declare any cost.
- No ReadOnlyInvocation guard; Action executors may mutate context state through SDK-provided handles subject to role and capability checks.
- Never cached. Each invocation runs fresh.
- **UCAN stem.** `outlet_call:{outlet_id}` or `outlet_call:*` (see §5.4.2.1 for parser semantics).
- **Chain depth.** Action cross-context calls use `max(1, max_chain_depth / 2)` as their budget. Default 4 when `max_chain_depth` is default 8.

**Default.** `OutletKind::Action` is the default when `kind` is absent in an otherwise-valid registration (fail-safe). SDKs SHOULD surface `kind` as a required field in application APIs even though the wire format tolerates absence.

**Chain amplification rule (§6.2).** A Query outlet invocation MUST NOT transitively invoke any Action outlet through cross-context hops. The reverse is permitted — an Action invocation MAY transitively invoke Query outlets. The runtime enforces this at the cross-context consent gate: on every hop, the runtime checks `hop.kind` against the originating request's `kind` and rejects Query→Action amplification with `OutletErrorClass::Authorization::AmplificationViolation`. This prevents a "free" read from being laundered into a paid write.

**Misdeclaration signal.** Any invocation that trips `QueryViolation` at runtime (an executor attempted a write inside a ReadOnlyInvocation) is recorded as an operator-attributable signal: the `OutletVerified` event for that outlet carries `integrity_ok: false` with reason `query_misdeclaration`, and participation records (§7.3.2) attribute the failure to the outlet's `operator_did`.

#### 5.4.2.1 UCAN Capability Stem Parser

The two stems `outlet_query:` and `outlet_call:` are parsed with a fixed two-step algorithm:

1. **Literal prefix match.** The parser accepts only the literal byte sequences `outlet_query:` or `outlet_call:` (case-sensitive, UTF-8). Any other prefix — including abbreviations, trailing-colon variations, or concatenations such as `outlet_query:call:foo` — is a `Capability::new` parse failure and MUST NOT be admitted as either stem. The colon is part of the stem, not a separator.
2. **Opaque suffix with outlet_id validation.** Everything after the prefix is the suffix. The suffix is either `*` (wildcard, matching `Capability::OutletQueryAll` / `OutletCallAll`) or a single outlet_id matching the regex `^[a-z0-9_-]{1,128}$`. No further `:` characters appear in a valid suffix; a colon in the suffix fails parsing (this blocks the `outlet_query:call:foo` parser-differential where a naive split-on-colon implementation would accept it).

Bridge and SDK parsers MUST apply this algorithm identically. The single canonical parser is `Capability::new` (`crates/scp-protocol/src/context/roles.rs`); every bridge routes through it.

The underscore in the wire form is deliberate: UCAN resource strings historically use `-` or `_` to disambiguate prefix from suffix, and `outlet:query:` (two colons) would require three-way parsing that invites prefix-vs-suffix ambiguity. The SDK-facing display form `outlet:query:{id}` / `outlet:call:{id}` is a pretty-print alias; it round-trips through `Capability::new` and `Capability::to_string` but is not the wire form. Pre-rename `tool:invoke:` / `tool_invoke:` / `tool:register` / `tool:interface` strings are hard-rejected (SCP-OUT-014): the parser returns a parse failure rather than mapping them onto any outlet capability.

### 5.4.3 Query Result Cache (Deferred)

A shared operator-signed relay-hosted Query result cache was drafted during the outlet redesign but pulled from initial scope before merge. Concrete design questions blocked it — relay-side authentication and authorization boundaries for cache reads (the cache must be membership-gated but relays are not membership-aware); interaction with per-member pseudonym routing (§9.10.4), which prevents the relay from grouping hits on a single routing ID without leaking subscribership; and the billing semantics of a paid Query operator serving an unbounded cached audience. Until the cache ships, §5.4.2 marks Query as "cacheable" as a semantic property of the kind, not as a claim that a cache exists; every Query invocation executes live. Implementations MUST NOT silently add a cache layer — a cache-like optimization that is not specified here is a protocol divergence, because it changes what the outlet-invocation event records and what the operator signs for.

### 5.4.4 Outlet Error Taxonomy

Every outlet failure — at registration, authorization, input validation, execution, output validation, billing, transport, or governance — surfaces as a single typed envelope, the `OutletError`. The taxonomy is deliberately **compact**: a small, fixed set of numeric codes carries the machine-actionable class of failure, and a dot-separated **slug** carries the fine-grained distinction. New failure conditions are minted as new slugs under an existing code, not as new codes. This keeps the code space bounded and stable across protocol rounds while still letting operators and SDKs disambiguate to the exact condition.

> **Provenance note.** This section documents the error registry the reference implementation ships in `crates/scp-protocol/src/context/outlets/error_codes.rs` and the envelope in `outlets/errors.rs`. It was authored to describe the shipped behavior faithfully; where §5.4.2 already names conditions (`query-cost-violation`, `query-violation`, `amplification-violation`), those names are the Protocol/Authorization-class slugs defined here.

**Error classes.** Every `OutletError` carries exactly one of **eight** root classes (`OutletErrorClass`). The class is the coarse routing key; SDKs render it as a sealed type (Python subclass tree, TypeScript tagged union, Swift `enum`, Kotlin sealed class). On the wire the class is the lowercase variant name (`"protocol"`, `"authorization"`, …). Each class owns a contiguous decimal code sub-range inside the `SCP-OUTLET-6100..6199` block:

| Class | Code range | Meaning |
|-------|-----------|---------|
| `Protocol` | `6100..6109` | Registration, validation, classification, session-lifecycle violations. |
| `Authorization` | `6110..6119` | UCAN / caveat / capability / attenuation / amplification denials. |
| `Input` | `6120..6129` | Input schema, size, type, range violations. |
| `Execution` | `6130..6139` | Handler panic, timeout, non-determinism, credit/stream exhaustion, cancel-ack timeout. |
| `Output` | `6140..6149` | Output schema, size, serialization violations. |
| `Economic` | `6150..6159` | Budget, insufficient funds, adapter failure, pricing, escrow overflow. |
| `Transport` | `6160..6169` | Relay unavailable, cross-context bridge failure, rate limiting, concurrency caps. |
| `Governance` | `6170..6179` | Deregistration, suspension, ceiling exceeded, active consequence. |

**The compact code registry.** Only seventeen codes are allocated across the `6100..6199` sub-block — the design target is "compact," roughly one to two codes per class. Every allocated code has a class, a canonical **default slug**, and a default retry policy:

| Code | Class | Default slug | Default retry |
|------|-------|--------------|---------------|
| `SCP-OUTLET-6100` | `Protocol` | `protocol.violation` | Never |
| `SCP-OUTLET-6101` | `Protocol` | `protocol.session-id-conflict` | Never |
| `SCP-OUTLET-6110` | `Authorization` | `authorization.denied` | Never |
| `SCP-OUTLET-6114` | `Authorization` | `attenuation.mask-width-violation` | Never |
| `SCP-OUTLET-6115` | `Authorization` | `authorization.salt-rotation-unjustified` | Never |
| `SCP-OUTLET-6120` | `Input` | `input.schema-violation` | Never |
| `SCP-OUTLET-6130` | `Execution` | `execution.handler-panic` | Never |
| `SCP-OUTLET-6131` | `Execution` | `execution.credit-exhausted` | Immediate |
| `SCP-OUTLET-6132` | `Execution` | `execution.stream-cap-exhausted` | Backoff 1s..30s |
| `SCP-OUTLET-6133` | `Execution` | `execution.credit-stall` | Backoff 1s..30s |
| `SCP-OUTLET-6134` | `Execution` | `execution.stream-idle-reclaimed` | Never |
| `SCP-OUTLET-6135` | `Execution` | `execution.cancel-ack-timeout` | Never |
| `SCP-OUTLET-6136` | `Execution` | `execution.stream-max-duration-reclaimed` | Never |
| `SCP-OUTLET-6140` | `Output` | `output.schema-violation` | Never |
| `SCP-OUTLET-6150` | `Economic` | `economic.insufficient-funds` | Never |
| `SCP-OUTLET-6160` | `Transport` | `transport.relay-unavailable` | Backoff 1s..30s |
| `SCP-OUTLET-6170` | `Governance` | `governance.outlet-deregistered` | Never |

Every other code in `6100..6199` — the intra-class gaps (`6111`, `6137`, …) and the reserved tail `6180..6199` — is **unallocated**. The registry lookups (`error_code_to_class`, `error_code_to_default_slug`, `error_code_to_retry_policy`) return "none" for any unallocated or out-of-sub-block code. Reserving the gaps lets future conditions that genuinely need a distinct *code* (rather than a new slug under an existing code) take a stable number without renumbering.

**Slugs.** The slug is the fine-grained condition name. It MUST match the regex `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$` — lowercase ASCII, dot-separated, each segment 1–64 characters and starting with a letter. Multi-segment slugs are normal (`transport.concurrent-streams-per-invoker`, `attenuation.mask-width-violation`). A slug's leading segment is normally the lowercased class name (`authorization.*` under `Authorization`, `execution.*` under `Execution`), so a slug maps deterministically back to its class via `slug_to_class`. Multiple slugs share one code: e.g. `SCP-OUTLET-6110` covers `authorization.denied`, `authorization.expired`, `authorization.revoked`, `authorization.missing`, `authorization.attenuation-violation`, and the caveat-enforcement slugs (`authorization.mint-limit-exceeded`, `authorization.time-box-violation`, `authorization.rate-exceeded`, `authorization.cumulative-exceeded`, `authorization.adapter-not-allowed`), while the distinct attenuation-invariant failures (`attenuation.*`) get their own code `SCP-OUTLET-6114` so operators can filter them apart from the catch-all denial. Code `SCP-OUTLET-6120` (Input) similarly carries the SDK-level range-validation slug `input.invalid-grant` alongside its default `input.schema-violation`: the SDK `Credit` newtype factory raises it (surfaced as the `InvalidGrant` error) when a caller-supplied credit grant is zero or exceeds the `u32` range, rejected before the grant is signed. It rides an existing code as a new slug — not a new numeric code — and carries the **Input** class, mirroring the §5.4.5 precedent where an out-of-bound caller-supplied `estimated_chunk_count` surfaces as `input.estimate-exceeds-bound` (Input): a bad caller-supplied numeric scalar is an input range violation, not a Protocol-shape or Authorization failure.

**Cross-class slug (exception).** `protocol.interface-spam-cost` carries a `protocol.` prefix but maps to the **`Economic`** class (code `SCP-OUTLET-6150`): the failure is an economic one (the §6.2.0.1 quadratic anti-spam fee was insufficient), but the *rule* that sets the fee lives at the protocol layer, so the slug keeps the rule's home for searchability while the class records the true semantics. It is the single slug whose leading segment does not equal its class name.

**Query-oracle collapse (`authorization.denied`).** Code `SCP-OUTLET-6110` with slug `authorization.denied` is the deliberate collapse target for the query-oracle protection. A caller that lacks the disambiguating capability stem on a target outlet receives exactly this `(code, slug)` pair regardless of whether the outlet is registered, deregistered, or has never existed — the error is identical across all three, so a probing caller cannot use error variation to enumerate which outlets exist. Only a caller holding the requisite stems ever sees a differentiated slug (e.g. `authorization.attenuation-violation`). The *code* stays `SCP-OUTLET-6110` in every case; only the slug varies, and only for callers already authorized to see the distinction.

**Retry guidance.** Every envelope carries a `RetryPolicy` (`Never`, `Immediate`, `After{delay}`, `WithBackoff{min,max}`) so a caller can decide to retry without re-classifying the error. Deterministic rejections (Protocol, Authorization, Input, Output, Economic, Governance, and broken-handler Execution faults) default to `Never` — retrying the same request reproduces the error. Idempotent credit exhaustion (`SCP-OUTLET-6131`, shared with the receiver-side `execution.stream-gap` cancel-and-rerun mitigation) defaults to `Immediate` (the framework refreshes credits / the caller reruns). Back-pressure conditions — the node-level concurrent-pump ceiling (`SCP-OUTLET-6132`), credit-stall (`SCP-OUTLET-6133`), and transport faults (`SCP-OUTLET-6160`) — default to `WithBackoff` over `1s..30s`. The node-level ceiling rejection carries its own code (not `SCP-OUTLET-6131`) precisely so the retry policy — keyed on the code — is `WithBackoff` rather than the credit band's `Immediate`: retrying immediately against a saturated node just re-fails. Receivers MAY override the default from contextual signals (e.g. a `transport.rate-limited` envelope carrying a `retry_after_secs` hint).

**Envelope wire form.** The `OutletError` serializes as a `MessagePack` map with numeric field tags: `1` code, `2` slug, `3` class, `4` message, `5` retry, `6` typed per-class detail, `8` cross-context source-chain, `11` `pad_nonce`, `12` `registration_event_id`. Tags `7`, `9`, `10` are reserved; tags `13+` are reserved for future extension. Any unknown tag (`7`/`9`/`10`/`13+`) is preserved verbatim and round-trips byte-identical, so an old SDK never drops a field a newer emitter added. The `detail` (tag 6) is a typed shape selected by the class (each class declares its expected detail shape; a class with no detail omits the tag, and a shape mismatch is rejected at construction). The `message` (tag 4) is `HMAC-SHA-256(outlet_message_key, catalog_key)[..32]` — the on-wire message is opaque to non-members, who cannot reverse it; members look up the registered `message_catalog` under the `registration_event_id` (tag 12) to recover the human-readable template. `pad_nonce` (tag 11) is a fresh per-envelope CSPRNG nonce that keys the pseudonymization of the cross-context hop trail; both `pad_nonce` and `registration_event_id` are emitted **unconditionally** (never omitted) so their presence cannot itself act as a side-channel oracle.

### 5.4.5 Progressive Output (Streaming)

This section specifies the **streaming** delivery mode (§6.2.5, ADR-061). Streaming and unary are **distinct** invocation modes with distinct committed integrity artifacts: a unary invocation commits `output_hash`, a streaming invocation commits `stream_manifest_hash` — a unary call is **not** modeled as a degenerate one-chunk stream (ADR-061 supersedes that framing). The wire types below carry a streamed result.

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
                                          // session-pinned caveats_binding (§6.2.1).
  timeout_ms:             u32,             // absolute stream timeout; 0 = use context default
                                          //   (ContextParams::stream_max_duration_secs; §5.4.5
                                          //   "Universal seal-phase reclamation"). Effective cap
                                          //   = min(timeout_ms, stream_max_duration_secs * 1000)
                                          //   when != 0 (both compared in ms).
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

**`effective_caveats` MUST be the VALIDATED-NARROWED set, not an unverified leaf assertion (conformance clarification).** The `effective_caveats` bound into `caveats_binding` at outlet-stream open are NOT the leaf token's `nb` field taken at face value. Before computing (and pinning) the binding, the receiver MUST resolve the caveats from the presented proof chain's leaf token `nb` field (§7.3.8 — the canonical wire location for invocation caveats) and run the §7.3.8 delegation-chain checks over the presented chain: **Step 7b** (per-edge caveat `narrow()` — every child's caveat set is no looser than its parent's, rejecting any widening) **and Step 11b** (time-box — `valid_from` / `valid_until` / `hours_of_day` / `days_of_week` evaluated against the current clock). Only the set that survives Step 7b narrowing (and is gated by Step 11b) is admissible as `effective_caveats`. A receiver that binds the raw leaf `nb` without running 7b/11b over the chain would pin — and then enforce, via the per-chunk `caveats_binding` and the `min(credit_window, max_calls)` cumulative billing ceiling — a caveat set the delegation chain never actually authorized. Equivalently: the leaf `nb` is the invoker's *claim*; `effective_caveats` is what the chain *grants*. §7.3.8 already mandates 7b/11b at every UCAN validation (this is a conformance clarification, not a new requirement); this clause states that the outlet-stream-open caveats_binding consumes the post-validation narrowed result so the binding — and every downstream cumulative-ceiling and per-chunk enforcement that depends on it — is grounded in validated authority rather than an unverified assertion.

**JCS `Option` serialization rule (cross-SDK byte-for-byte match).** Absent `Option`-typed fields in `effective_caveats` — `amount_max_per_call`, `amount_max_cumulative`, `valid_from`, `valid_until`, `hours_of_day`, `days_of_week`, `max_calls`, `rate_window`, `input_schema`, `allowed_adapters`, `allowed_target_dids`, `origin_kind` when absent — are **OMITTED** from the JCS encoding, NOT serialized as explicit `null`. Concretely, `canonical_jcs(effective_caveats)` applies standard serde-with-`skip_serializing_if = "Option::is_none"` semantics before running RFC 8785 canonicalization: a `None`-valued field produces no key-value pair in the JSON object, and RFC 8785's lexicographic sort then orders only the present keys. An SDK that serializes `None` as `"field_name": null` produces a distinct byte string and a distinct `caveats_binding` preimage, and the resulting stream-open is rejected. All four SDKs MUST use the omit-none convention. A cross-SDK conformance fixture covers this: a caveat set `{ amount_max_per_call: Some(100) }` produces the same 32-byte `caveats_binding` from Python (PyO3), TypeScript (napi-rs), Swift (UniFFI), and Kotlin (UniFFI) regardless of the other 11 fields' absence — verified by `cargo test -p scp-testing --test outlet_caveats_binding_conformance`.

**Binding-pinning invariant.** At first `OutletStreamOpen`, the receiver records `(request_id → {context_id, outlet_id, caveats_binding, stream_epoch, invoker_pk, credit_counter, monotonic_seq_cursor})` in its stream table for the lifetime of the stream (bounded by `timeout_ms`, `stream_credit_stall_secs`, or terminal chunk arrival, whichever fires first). `stream_epoch` is the hosting context's MLS epoch counter captured at `OutletStreamOpen` acceptance and is the value committed into the `SCP-OUTLET-CREDIT-V1:` grant preimage — pinning it in the stream table lets the executor reject credit grants whose preimage epoch does not match the stream's accept-time epoch even if `request_id` and `caveats_binding` are colliding across a binding-eviction race. Any subsequent `OutletStreamOpen` carrying the same `request_id` but a different `caveats_binding` is rejected as `AttenuationViolation`. This closes the "two opens with the same request_id under different caveats" attack without relying on undetectable later-chunk inspection. The per-stream `CreditCounterStore` entry shares the pinning record's lifetime — the credit counter and `monotonic_seq_cursor` are stored alongside the pinned `caveats_binding` so a single eviction signal (stream terminated, timeout fired, credit-stall cancel) clears both at once. Once the stream terminates, the receiver MAY evict the pinning record and associated credit state; a fresh `request_id` is required for a new stream.

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

See also the cross-context outlet invocation modes (§6.2.5) and the cross-context outlet invocation saga (§6.2.4; ADR-061), which govern these parameters at cross-context acceptance.

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

**Chunk-signature replay resistance.** Replay resistance of the per-chunk signature rests on `request_id` (UUIDv7) uniqueness together with `caveats_binding` pinning — `stream_epoch` is deliberately NOT part of the `SCP-OUTLET-CHUNK-SIG-V1` preimage (unlike the `SCP-OUTLET-CREDIT-V1` grant preimage below, which does bind `stream_epoch`). Each stream carries a unique `request_id`, and `caveats_binding` — which commits `ucan_cid`, `request_id`, `invoker_did`, `estimated_chunk_count`, and the narrowed caveats — is bound into every chunk preimage; a chunk signature therefore cannot be replayed across streams or across caveat shapes, so the epoch is unnecessary in the chunk preimage and its omission is intentional (verified by the cryptographer review).

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
                                   //   captured at OutletStreamOpen acceptance
                                   //   (see the Binding-pinning invariant above);
                                   //   pinned in the stream record alongside
                                   //   caveats_binding at first open)
  || caveats_binding               // 32 bytes, the stream's caveats_binding
)
```

The executor's credit accounting admits a grant only if (a) the signature verifies under the invoker's public key recorded at stream open, (b) `context_id`, `outlet_id`, `stream_epoch`, and `caveats_binding` bound into the preimage match the pinned values for this `request_id` at first open, and (c) `monotonic_seq` strictly exceeds every previously accepted `monotonic_seq` for this `request_id`. Binding stream identity (`context_id`, `outlet_id`, `caveats_binding`, `stream_epoch`) into the signed preimage closes the cross-stream and cross-epoch replay surface: a grant signed for stream A in context X at epoch E cannot be replayed as a valid grant for stream B in context Y or for a different epoch even under contrived `request_id` collisions or binding-eviction races. Duplicates and regressions are rejected as `OutletErrorClass::Authorization::CreditReplay` and do NOT advance the credit counter. This closes the relay-drop/inject DoS surface: a malicious relay cannot forge grants to starve the executor, and cannot replay stale grants to bypass the invoker's intended flow control. The `SCP-OUTLET-CREDIT-V1:` separator is registered in §9.18.2.

**Credit-grant escrow top-up.** Each validly accepted `OutletStreamCredit` grant on an Action outlet with `cost.amount > 0` automatically tops up the stream's escrow by `cost.amount × grant`, computed via `checked_mul` — arithmetic overflow rejects the grant with `OutletErrorClass::Economic::EscrowOverflow` and does NOT advance the credit counter. If the invoker's available balance is below the top-up amount at the moment of grant acceptance, the grant is rejected with `OutletErrorClass::Economic::InsufficientFunds` and the credit counter does not advance. The operator only bills chunks emitted while covered by topped-up escrow; a grant that fails top-up does not authorize further billable chunks. For Query outlets and zero-cost outlets no top-up is performed.

**Ordering and gaps.** `sequence` values are strictly monotonic per `request_id`. A receiver that observes a gap (missing sequence) MUST cancel the stream with `OutletErrorClass::Execution::StreamGap` and SHOULD rerun. MLS has no primitive for per-message retransmit and adding one at the SCP layer would require reintroducing a per-recipient unicast channel that MLS deliberately eliminates — so the mitigation is cancel-and-rerun, not retry.

The **receiver** bound by this MUST is the invoker-side SDK framework — the `invoke()` `InvocationHandle` drain that consumes the chunk stream — mirroring the receiver-side revocation-recheck locus (see "Revocation re-check cadence (receiver-side)" below). The drain tracks the expected next `sequence` (contiguous from 0) and, on any non-contiguous chunk, surfaces `StreamGap` (`SCP-OUTLET-6131`) and cancels the stream by the locus appropriate to where the receiver runs (see the carve-out below). Because the same-context transport is a lossless ordered channel and the executor pump assigns `sequence` consecutively, this check cannot fire on a same-context stream — it is a transport-agnostic receiver invariant that becomes load-bearing only when the invoker consumes chunks over a lossy transport (cross-context / relayed streaming).

**Co-located vs. remote receiver (cancel locus).** *How* the gap MUST cancels the stream depends on whether the receiver is co-located with the executor pump:
- A **co-located** receiver (an in-process / same-node invoker whose SDK framework can read the runtime state) cancels via the signed `OutletCancel` path — it reads the runtime's live emission cursor from `StreamSessionHandle::current_next_emission_seq` and binds that exact value as `next_seq` (see "Cancel signature" below; the cancel preimage's `next_seq` is runtime-derived and "never a value supplied by the caller").
- A **remote** invoker-side receiver — a cross-context / browser invoker per ADR-057, which participates but does not coordinate — structurally cannot read the executor's emission cursor (it holds only its own receive cursor). It therefore MUST NOT sign an `OutletCancel` (a caller-supplied `next_seq` is exactly the forgery the "Cancel signature" block below rejects). Instead it surfaces `StreamGap` (`SCP-OUTLET-6131`) to its caller and stops replenishing credit; the stream is reclaimed authoritatively on the node by the executor's credit-stall (`stream_credit_stall_secs` → `SCP-OUTLET-6133`) or `timeout_ms`, which flushes the stream-table entry, releases escrow, and frees the concurrent-pump permit. These are the two loci of the same cancel-on-gap MUST, not alternatives to it: the co-located receiver cancels directly, the remote receiver induces the node to cancel. The runtime pump is the *producer* in the same-context case and therefore has no gap to detect; any additional authoritative gap-detection introduced at a cross-context reassembly layer is reconciled with this SDK-drain check as defense-in-depth (as the revocation dual-locus is), not as a replacement.

**UCAN check locus.** The UCAN presented in `OutletStreamOpen` is validated exactly once, at open. Every chunk carries the `request_id`; the receiver correlates to the open and does not re-present or re-validate. This prevents UCAN revocation races mid-stream from splitting a stream into authorized and unauthorized halves.

**Revocation re-check cadence (receiver-side).** Because an executor may never voluntarily reach a checkpoint, the stream receiver's SDK framework MUST enforce its own periodic re-check of the opening UCAN's revocation status during the entire active lifetime of the stream. Every `ContextParams::stream_ucan_recheck_secs` (default 10, range [1, 60]; registered in §9.18.B) the framework consults its revocation state and, if the token has been revoked since stream open, terminates the stream with `OutletErrorClass::Authorization::RevokedMidStream` (code `SCP-OUTLET-6110`, slug `authorization.revoked-mid-stream`) regardless of whether the executor has voluntarily reached a checkpoint. Already-emitted chunks remain authorized; the stream closes at or before `stream_ucan_recheck_secs` after the revocation event regardless of executor behavior. The executor also MAY re-check at its own checkpoints; the framework-side cadence is the worst-case upper bound on exposure and is not dependent on executor cooperation. SDK wrappers for `invoke()` are responsible for plumbing this re-check task into the stream's lifecycle.

**Context teardown vs. revocation (round 8).** The same framework re-check loop that enforces the revocation cadence above also observes the hosting context's liveness. When the hosting context is closed or the operator is evicted/leaves while a stream is active, the framework terminates the stream with `OutletErrorClass::Protocol::ContextClosedMidStream` (code `SCP-OUTLET-6101`, slug `protocol.context-closed-mid-stream`) — NOT with `RevokedMidStream` (Authorization class). The two conditions are distinct and MUST NOT be conflated:

- **Revocation** (`authorization.revoked-mid-stream`, Authorization class) means the *invoker's UCAN* was revoked. It is an authorization-boundary event and the correct audit signal is "the caller's right to invoke was withdrawn."
- **Context teardown** (`protocol.context-closed-mid-stream`, Protocol class) means the *hosting context* ceased to exist underneath an otherwise-valid authorization. The caller's UCAN was never revoked; the stream ended because its substrate disappeared.

Mapping a teardown to `RevokedMidStream` would (a) write a false audit signal — a behavioral record implying the caller's credential was revoked when it was not — and (b) hand an adversary a DoS lever: an operator able to trigger a teardown (e.g., by leaving the context) could synthesize a revocation-class audit entry against an arbitrary in-flight invoker. Round 8 closes this by giving teardown its own Protocol-class terminal cause. When both conditions are observable in the same re-check tick (a context closed AND the token revoked), **context teardown takes precedence** — the stream's substrate is already gone, so the Protocol-class teardown is the more proximate and accurate cause.

**Node-level concurrent-pump ceiling (round 8).** Distinct from the three per-context `OutletStreamOpen` admission caps (per-invoker / per-origin-invoker / per-outlet) above, each node enforces a single node-wide ceiling on the total number of concurrently-running stream pumps across all contexts hosted on that SCP instance, governed by `max_concurrent_outlet_stream_pumps` (default 4096, range [1, 65536]; per-instance state per ADR-048 — NOT a process-global). The ceiling bounds the runtime's aggregate task/memory footprint regardless of how the per-context caps are configured across many contexts. A permit is acquired AFTER all per-context admission/escrow/binding gates pass; on saturation the open is hard-rejected with `OutletErrorClass::Execution::StreamCapExhausted` (code `SCP-OUTLET-6132`, slug `execution.stream-cap-exhausted`, retry `WithBackoff 1s..30s` — the node is at capacity, so the caller backs off rather than retrying immediately) and no stream-table entry, escrow reservation, or admission counter is mutated. The permit is held for the exact lifetime of the pump task and released when the pump exits — normal close, terminal chunk, cancel-ack, or panic — so a panicking pump cannot leak a permit. A rejected open does not consume a permit.

**Cancellation and billing boundary.** The existing `OutletCancel` message cancels a stream by `request_id`. The executor-side framework handles `OutletCancel` receipt as follows: (1) it records `cancel_ack_seq = current emission cursor` (the next-to-emit sequence number, pinned at the moment of cancel arrival, so chunks already in flight at that sequence are NOT counted as billable above the cutoff); (2) it arms the `stream_cancel_ack_secs` timer (default 5s); (3) it emits exactly one terminal chunk (`End` or `Error { terminal: true }`) within the window — this terminal chunk is the **cancel-ack**, and its `sequence` is the authoritative **cancel-ack sequence** written into the event log; (4) on terminal chunk emission the framework flushes stream state (clears the pinning record from the stream table, releases escrow, releases the chain-depth slot). If the timer fires before the executor emits a terminal chunk, the framework forces the stream closed with `OutletErrorClass::Execution::CancelAckTimeout` (code `SCP-OUTLET-6135`, slug `execution.cancel-ack-timeout`) and writes its own terminal `Error { terminal: true }` chunk at the next-to-emit sequence. A receiver MAY ignore chunks with sequence greater than the cancel-ack sequence, but the executor MUST NOT emit Data/Progress chunks with sequence greater than the cancel-ack sequence.

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

**FFI bridge caller authentication (CRITICAL #1 / SCP-OUT-037 round-8).** Every FFI bridge that exposes the streaming control plane (`outlet_stream_grant_credit`, `outlet_stream_cancel`, `outlet_stream_terminate`) MUST require the caller to identify itself via a `caller_did` parameter and verify the value matches the `invoker_did` pinned at stream open before signing under the registry-held invoker key. Without this gate, any in-process code that observes a `request_id` could drain credit, force-cancel, or terminate any concurrent stream — the round-7 signature gates above are vacuous because the bridge wields the signing key on behalf of the caller. The verification SHOULD slug as `authorization.denied` (`SCP-OUTLET-6110`) on mismatch; the runtime layer's signature check remains in force as defense-in-depth.

**Billing semantics.** Streaming-native invocation uses an escrow-and-reconcile model so early termination does not leave the economic layer inconsistent.

- **At open** (Action outlets with non-zero cost only): the runtime escrows an upper-bound estimate from the invoker's balance. The estimate is `cost.amount × estimated_chunk_count`, computed via `checked_mul` — an arithmetic overflow is rejected as `OutletErrorClass::Economic::EscrowOverflow` before any state is committed. `estimated_chunk_count` is declared in the open and is structurally bounded by `min(credit_window, caveats.max_calls.unwrap_or(u32::MAX))` — a declared estimate exceeding that bound is rejected at open with `OutletErrorClass::Input::EstimateExceedsBound` (the bound is the protocol's upper limit on how many billable chunks CAN flow regardless of executor behavior, so the escrow must not over-reserve beyond it). For outlets without declared cost or for Query outlets, escrow is zero and `estimated_chunk_count` is advisory.
- **Per chunk**: the operator accrues `cost.amount` per billable chunk (Data chunks; Progress, End, Error are never billed). Chunks beyond the cancel-ack sequence are NOT billed even if they arrive (the operator violated cancel semantics; the invoker does not pay for the violation).
- **At close** (`End` received or stream terminated): the runtime issues a `PaymentReceipt` (§19.15.5) for the billed amount and refunds the unspent escrow to the invoker. A stream that terminates with `Error { terminal: true }` before any Data chunk refunds the full escrow; the operator does not bill for the failed execution.
- **Credit-stall cancel**: the stall cancel (`SCP-OUTLET-6133`) releases the escrow and the chain-depth slot. The operator is billed for Data chunks already delivered within the stalled window.

The event log records `chunks_billed: u32` separately from `stream_chunk_count`: the total chunk count includes Progress/End/Error, while `chunks_billed` is the count of Data chunks at or below the cancel-ack sequence that were validly delivered.

**Universal seal-phase reclamation — bounded self-refund of an abandoned stream (normative).** A streaming saga's seal-phase pump (ADR-061 *seal phase*; §6.2.5) MUST **force-settle over its durable chunk prefix** if the stream makes no forward progress, or exceeds an absolute duration — **regardless of whether any consumer is draining, and regardless of whether a terminal chunk ever arrives**. This closes the gap where the outer pump blocks on `inner_rx.recv()` (or on a wedged bounded forward channel) **forever**: an executor that finishes without emitting a terminal chunk, or a caller that abandons the stream and never drains, would otherwise leave the caller-side escrow **reserved indefinitely** with no client-held `SagaId` to reclaim it. Two independent deadlines bound the seal phase:

- **Idle deadline — `ContextParams::stream_seal_idle_secs` (default 45).** If the seal-phase pump makes **no forward progress** — neither forwards a chunk to the caller nor observes a terminal chunk — for `stream_seal_idle_secs`, it force-settles with terminal code `SCP-OUTLET-6134` (`execution.stream-idle-reclaimed`). This is a **distinct seam** from the credit-stall (`stream_credit_stall_secs`): credit-stall governs the **inner** executor→runtime credit exhaustion and is invoker-facing backpressure (`SCP-OUTLET-6133`); the seal-idle deadline governs the **outer** runtime→caller forward path (a wedged/undrained forward channel, or a silent executor holding credit) and is a money-safety reclamation backstop. Both are required; neither subsumes the other. **The effective idle deadline is clamped by construction, not by a config-rejection rule:** `effective_idle = max(configured stream_seal_idle_secs, stream_credit_stall_secs + STREAM_SEAL_IDLE_MARGIN)`, where `STREAM_SEAL_IDLE_MARGIN` is a small fixed constant (**1 s**). This makes `effective_idle > stream_credit_stall_secs` true **by construction** — so on a credit-stalled stream the credit-stall (`SCP-OUTLET-6133`) always fires strictly before the idle-reclaim and the recorded terminal code is **deterministic** — **without** any "reject the config" rule or standing deployer obligation to hand-maintain the inequality (a derived clamp recomputes correctly when `stream_credit_stall_secs` is retuned; a hand-maintained inequality rots). `stream_seal_idle_secs` remains a tunable knob (escrow-reclaim aggressiveness, default `45`); it is simply **clamped up** to the margin floor when configured too low, never rejected. The clamp MUST be applied mechanically wherever the effective deadline is derived (per §6.2.4 *Mechanical enforcement*), not left as config-time convention.
- **Max-duration cap — `ContextParams::stream_max_duration_secs`.** An absolute wall-clock ceiling on the entire seal phase, applied **unconditionally**, force-settling with terminal code `SCP-OUTLET-6136` (`execution.stream-max-duration-reclaimed`). This is the **context default backing `OutletStreamOpen.timeout_ms == 0`**, formalizing the previously-unregistered "`0` = use context default" backing for `timeout_ms` (§5.4.5 wire types) and closing the `timeout_ms == 0` ⇒ no-absolute-timeout ⇒ blocks-forever gap. The effective cap is `min(timeout_ms, stream_max_duration_secs * 1000)` — both operands compared in **milliseconds** (`timeout_ms` is already ms; `stream_max_duration_secs` is scaled by 1000), so a small explicit `timeout_ms` correctly wins over the seconds-valued context default — when the open declares an explicit non-zero `timeout_ms`, and `stream_max_duration_secs * 1000` when it declares `0`. (**Proposed default `900s` (15 min); the exact value is a product call — a long LLM stream can legitimately exceed the ~95 s unary bound (ADR-061 §3a), so this last-resort cap is deliberately generous because the §6.2.4 idempotent resume and the idle deadline already reclaim the common abandonment cases. The `900s` default MUST be validated against realistic long-running agentic / LLM stream durations before ship; a context that expects streams to run longer than 15 minutes MUST raise `stream_max_duration_secs`, or those legitimate streams will be force-settled mid-flight.**)

**Deterministic terminal code on a coincident max-duration tie (normative).** The idle-vs-credit-stall ordering is already deterministic **by construction**: the `effective_idle` clamp above guarantees `effective_idle > stream_credit_stall_secs`, so the credit-stall (`SCP-OUTLET-6133`) always fires strictly before the idle-reclaim (`SCP-OUTLET-6134`). The only residual coincidence is the absolute max-duration cap firing in the same tick as either of them: in that case the **max-duration cap wins** and the recorded `stream_terminal_status` code is `SCP-OUTLET-6136` (`execution.stream-max-duration-reclaimed`) — the absolute cap is the harder, non-negotiable bound, so attributing the close to it is the more accurate audit signal. This coincidence is measure-zero (the max-duration cap is far larger than both other timers) and the money outcome is identical in every case (all force-settle over the same durable prefix), so this precedence changes only the recorded code, never settlement.

On **either** deadline firing, **force-settle** proceeds **identically to a normal terminal close** over the durable prefix — the ADR-061 *mid-stream crash: seal-prefix-and-close* mechanism, here triggered by a deadline rather than a crash-recovery sweep:
1. **Durably record the seal cutoff — the last-sealed `sequence` and the prefix `billed_count` — BEFORE signing the receipt.** The `stream_manifest_hash` the receipt commits must be reproducible on replay from the `SagaId`-keyed durable capture; a receipt signed over a cutoff that was not first durably recorded could not be reproduced byte-for-byte after a crash, breaking the ADR-061 durable-root-capture obligation.
2. Finalize the RFC-6962 Merkle frontier at that recorded cutoff.
3. Sign the streaming receipt over the truncated manifest.
4. **Settle escrow (refund = reserved − billed).**
5. Record both event logs and reach `Committed`.

The reclaimed `OutletInvokedEvent` MUST populate `cancel_ack_seq` with the recorded seal cutoff (the `chunks_billed` ceiling), so the **`chunks_billed_ref` log-insert check (below) passes over the truncated manifest** — a reclaimed close is a truncated close, and without a populated ceiling the `chunks_billed == chunks_billed_ref` wire-layer check would reject the event. **`cancel_ack_seq` here is the billing/truncation *ceiling*, not a signal that a caller-initiated `OutletCancel` occurred** — no cancel was received on the reclamation path. A consumer distinguishes a reclamation from an actual cancel by the `stream_terminal_status` code (`SCP-OUTLET-6134`/`6136` for reclamation, versus a cancel-driven close), **never** by the mere presence of a populated `cancel_ack_seq`. `billed ≤ delivered` holds (the `CancelAckTracker` billing ceiling makes the truncated close well-defined). Crucially, the seal-phase pump **owns these timers itself** and force-settles **without relying on any caller-side drain or cancel** — the reclamation is fully **server-side**, so it fires even when the FFI open ran on a **detached runtime task** (UniFFI `runtime().spawn().await`; the Kotlin streaming surface) whose caller-side cancellation cannot drop the Rust future. This makes **seal-close — and therefore escrow settlement (`settle_at_close`; ADR-049 §3a streaming-saga slot release) — an always-reached terminal**, guaranteeing escrow always refunds **without** the client-held `SagaId`.

**Scope — same-context streams share the reclamation, not the transactional envelope (normative).** `timeout_ms` is a common `OutletStreamOpen` field, not a cross-context-only one, and its `== 0` case is now **universally** backed by `stream_max_duration_secs` (above). Consequently the **abandoned-stream reclamation** is **not** limited to the cross-context streaming saga: a same-context `outlet stream` whose invoker-side `InvocationHandle` is dropped (or whose SDK-drain wedges) is bounded by the **same idle/max-duration deadlines**, and on firing the runtime performs the **same escrow/credit settlement (refund = reserved − billed) and releases the concurrent-pump permit and stream-table entry** — closing the identical root-cause orphan on the same-context `InvocationHandle` / Python-reference-drain path. What a same-context stream does **NOT** get is the transactional-envelope machinery, which is specific to the cross-context streaming saga (ADR-061): a best-effort `outlet stream` has **no signed receipt, no atomic dual event-log, and no `Committed` saga terminal** — its reclamation simply settles the economics and frees the pump, it does not seal a `stream_manifest_hash` into a receipt or drive a saga FSM to `Committed`. So this is a **money-safety broadening on the shared runtime pump** (the reclamation deadlines + settlement + permit release live on the pump, which both modes share), **not** an extension of the transactional guarantee to same-context streams.

**Live-saga reattach (normative; cross-ref §6.2.4 saga-open idempotency).** When a caller resumes an in-flight streaming saga via the §6.2.4 idempotency index, the FFI surface returns a `LiveStreamingSaga` handle reattached to the running pump. Reattach delivers the terminal receipt / manifest root and **chunks produced after reattach**; it does **NOT** backfill chunk payloads produced before reattach, because the durable capture is an **O(log n) Merkle frontier of hashes, not a payload buffer** (ADR-061; the no-buffering forward-as-produced invariant of *Cross-context streaming* below). A caller that must not miss payloads MUST treat a gap as `StreamGap` (*Ordering and gaps* above) and rerun. **Cross-process reattach carries no payload backfill:** an in-process resume can re-hand the live in-memory chunk receiver, but a resume from a *different process* than the hosting node has no live receiver to re-hand and the durable capture holds only hashes — so a cross-process resume delivers at most post-reattach chunks plus the terminal receipt, never the already-delivered payload prefix. **Money-safety does not depend on reattach**: the universal seal-phase reclamation above guarantees settlement even if the caller never resumes.

**`chunks_billed` is verifiable from the manifest.** Every leaf of the chunk manifest commits to a canonical chunk whose `payload` carries the `@type` discriminator (§5.4.5 wire types). For any event whose `stream_manifest_hash` and chunk sequence are known, an auditor computes the reference count

```
chunks_billed_ref = |{ i : leaf_i.payload."@type" == "data" && i <= cancel_ack_seq }|
```

The event log's recorded `chunks_billed` MUST equal `chunks_billed_ref`. An `OutletInvokedEvent` whose recorded `chunks_billed` does not match the value derivable from the manifest root, the sealed chunk sequence, and the cancel-ack sequence is a wire-layer rejection — the event is refused at log-insert time, not accepted-and-flagged. The cancel-ack sequence is recorded alongside `stream_terminal_status` in the event (absent when the stream terminated without cancel, in which case the ceiling is `u64::MAX` and the predicate reduces to `@type == "data"`). Because leaves cover the full canonical chunk including `@type`, `sig`, and the `caveats_binding` committed at chunk-signing, `chunks_billed_ref` is a function of the signed, committed stream — operators cannot over-bill by recording a higher count than their own signed manifest supports, and cannot under-bill without making a manifest that excludes already-delivered chunks.

**Cross-context streaming.** Streams span the §6.2 outlet-interface boundary. The **shared-member bridge is the human's SDK seam** (§6.2.0: *the human's SDK is the transport*), **not** a relay primitive. The bridge forwards each operator-signed chunk to the shared-member invoker **in-process as plaintext** — a sanctioned disclosure, because that invoker is a member of *both* the operating context B and the receiving context A (mirroring the same-context `invoke_outlet`, and the unary saga where the output returns to the invoker as bytes while the invoker's own event log records only `output_hash`, §6.2.4). Delivery to A's **other** members is then a normal **A-context application message**: the bridge seals each still-operator-signed chunk under A's MLS group key and sends it over the **existing encrypted-context MLS application-message transport (§9.7 MLS group, §9.8 Message Security, §9.16 Sender-Side Key Layer)** — the group key *is* the per-recipient re-encryption mechanism, and **no new relay cross-context routing primitive is introduced** (§6.2.0: "No relay-level cross-context routing is needed"). A's event log records only the 32-byte `stream_manifest_hash` (never chunk plaintext) — the streaming parity of the unary saga's `output_hash`-only caller log (§6.2.4). The operator's `SCP-OUTLET-CHUNK-SIG-V1` signature is **preserved end-to-end and never re-signed** by the bridge, so the per-chunk equivocation binding (above) survives the crossing: A's members verify B's operator signature directly. `chain_depth` is set at open and governs the whole stream — it is a field of the `OutletStreamOpen` (inherited onto the bridge's onward A-leg open from the incoming open), **not** of each `OutletStreamChunk`, so chunks do not carry, recompute, or check it. Credit is end-to-end: the originating invoker grants credit that propagates across the bridge. When a stream crosses the boundary **transactionally** — the **streaming saga** mode (§6.2.5, §6.2.4; ADR-061) — the cross-context receipt is the distinct **`SCP-XCTX-STREAM-RECEIPT-V1`** separator carrying the stream's `stream_manifest_hash` (the RFC-6962 Merkle root over the sealed chunk sequence, a fixed 32 bytes) directly — **NOT** an `output_hash`. This is the streaming counterpart to the unary saga's `SCP-XCTX-RECEIPT-V1` receipt (which commits `output_hash`, §6.2.4). Per ADR-061, the streaming receipt's manifest root is reproduced on replay from the `SagaId`-keyed durable capture finalized at stream-close (the seal phase), never by re-executing the stream; a third-party auditor holding only the receipt gets root-binding verification over the ordered, counted, per-chunk-signed sequence.

**Verification source at the crossing (normative).** A receiving context MUST verify each operator chunk signature against the `operator_pk`, the operating context's `context_id` (B), and the `caveats_binding` **pinned in the governed outlet-interface descriptor / at stream-open** (§6.2.0.1; the per-chunk signature preimage above binds `context_id`, `outlet_id`, and `caveats_binding`) — **never** against `operator_pk` / `context_id` / `caveats_binding` values the bridge supplies at delivery time. This is the streaming analog of §6.2.4's *Caller authentication* rule (the channel-authenticated identity governs, not envelope-asserted fields): a malicious bridge that could substitute the verification inputs could pass off chunks signed by a *different* operator, or for a *different* context it controls, as if they were B's — defeating the per-chunk equivocation binding. Pinning the verification inputs to the governed descriptor forecloses that substitution.

**Cross-context economy (best-effort is zero-escrow).** The best-effort cross-context bridge is **zero-escrow**: it serves Query outlets and zero-cost (`cost == None || cost.amount == 0`) Action outlets, propagating the invoker's credit grants end-to-end as **backpressure** — **credit is flow-control, not payment** — and performs **no caller-side escrow settlement**. Per **ADR-061**, caller-side escrow settlement is **saga-unique** (one of the three properties the transactional envelope adds over the best-effort *outlet stream* — atomic dual-log recording, the signed receipt, and caller-side escrow settlement). A best-effort cross-context open of a **paid** Action outlet (`cost.amount > 0`) is therefore **rejected**; a metered, paid cross-context stream MUST use the **streaming saga** (§6.2.4, §6.2.5). The zero-escrow gate rejects on **both** the registered `cost.amount` **and** the runtime per-chunk billing value supplied at open (`cost_per_chunk`): §5.4.5 (Per chunk) fixes `cost.amount` as the per-chunk accrual unit, so the two MUST agree, and the gate rejects if **either** is positive — a registration whose `cost.amount == 0` presented alongside a positive `cost_per_chunk` (or the reverse) is a split-source paid stream and is rejected, never admitted to the zero-escrow path.

**Event log shape.** A stream produces ONE `OutletInvokedEvent` at close, not one per chunk. The event carries:

```
OutletInvokedEvent {
  // Existing fields retained (invoker_did, outlet_id, input_hash, ...)
  stream_chunk_count:     u32,        // total chunks including terminal
  chunks_billed:          u32,        // Data chunks at or below cancel-ack sequence
  stream_manifest_hash:   [u8; 32],   // Merkle root over chunk leaves; see below
  stream_terminal_status: StreamTerminalStatus, // Ok | Error(code) | Cancelled
  cancel_ack_seq:         Option<u64>, // pinned cancel-ack sequence = the chunks_billed
                                       // ceiling; None when the stream terminated
                                       // without a cancel (ceiling = u64::MAX)
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

**Non-progressive executor on the streaming path.** An executor that produces its result as a single value (rather than emitting progressive chunks) still runs through the streaming surface as a degenerate stream of exactly two chunks: `Data(output)` followed by `End(output)`, committing `stream_manifest_hash` over that two-chunk sequence. SDKs MAY present a synchronous `invoke()` surface that collects such a stream into the final `End.aggregate`. This is **distinct from a unary invocation** (ADR-061's *plain outlet invocation* / *outlet invocation saga*), which commits `output_hash` and is **not** modeled as a stream (see the §5.4.5 preamble and ADR-061); choosing the unary delivery mode versus a non-progressive streaming executor is a registration/call-surface decision, not a wire coincidence.

**Rejected alternatives (for this section).** (1) A separate `OutletResponse` non-streaming *type*: rejected. Unary and streaming are distinct delivery modes (ADR-061), but they share a single `OutletInvokedEvent` shape — a unary event carries `output_hash` and leaves the stream fields at their no-manifest sentinels; a streaming event carries `stream_manifest_hash`. One event type spanning both modes avoids forking the pipeline into two response types with almost-but-not-quite identical semantics. (2) Per-chunk inclusion-proof API exposed on the SDK surface: deferred per above. The manifest root is sufficient for integrity; a proof API is a convenience over that primitive and can be added without a wire break. (3) Per-chunk UCAN checks: rejected because mid-stream revocation would split a single logical invocation into authorized and unauthorized halves, which is less legible than revoking-at-checkpoint.

## 5.5 Roles

Contexts define roles with specific permission sets within the capability ceiling. Roles determine which outlets an agent can invoke, what data it can access, whether it can invite others, modify settings, etc.

Properties of roles:

- **Visible before opt-in.** You see what role you'd get before joining.
- **Non-negotiable.** Agents cannot request or bargain for different roles. Take it or leave it. If you want a different role, ask the context creator (human to human) or create your own context.
- **Defined by context creator.** Custom roles beyond defaults are context-specific.
- **Governed by context governance model.** Role changes require whatever governance the context uses.

**Broadcast context roles.** Broadcast contexts (§5.14) extend the role system with two mode-specific roles that reuse existing primitives:

- **Author** — holds `messages:write` UCAN. Can publish broadcast-key-encrypted content. Authors are bounded (added via `role:assigned` events with role `author`). Each author maintains their own broadcast key with an independent epoch counter.
- **Subscriber** — holds `messages:read` (auto-granted on DID-authenticated registration in open broadcast contexts, or requiring an explicit admin-issued UCAN in gated broadcast contexts). Subscribers receive author broadcast keys on request. Subscribers are unbounded.

The author/subscriber distinction mirrors the writer/reader two-tier model from contexts with discovery outlets (§6.2.2B). Open broadcast subscriber registration follows the same DID-authenticated pattern as context reader-tier access.

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
- Invoke outlets (no `outlet:query:*`, `outlet:call:*`, `outlet:query:{id}`, or `outlet:call:{id}`).
- Invite members.
- Propose or vote on governance actions.
- Modify context metadata.
- Register or deregister outlets.

**Custom roles.** Context creators define custom roles by specifying a role name (string, max 64 chars, `[a-z0-9_-]`) and a permission set (subset of the ceiling). Custom role permissions MUST be a subset of the ceiling — a custom role cannot grant capabilities beyond the ceiling. Custom roles are stored in the context's role registry (`context/{id}/role/{role_name}` per §17.3) and visible in context metadata.

## 5.6 Membership

One agent per human per context. Membership is transparent — participants can see the member list, roles, and agent capability metadata. When you opt into a context, you know what you're walking into.

**Broadcast context membership.** Broadcast contexts use a two-tier membership model: authors (MLS-equivalent bounded writers) and subscribers (unbounded readers registered via DID-signed requests). Subscriber registration records membership via `MemberJoined` events with role `subscriber`. The member list includes both tiers. Subscriber count is visible in metadata.

### 5.6.1 Member Removal Is a Clean Teardown

**Member removal is a clean teardown.** When a member is removed from a context — by governance `RemoveMember`, by self-`leave`, or by a failed-join rollback — ALL per-DID role state for that DID is dropped in the same operation: the DID is removed from the member list (`members`), its role assignment (`assignments`), its cached granted capabilities (`member_capabilities`), AND its suspended-capability set (`suspended_capabilities`, §5.3.2). A suspension only ever DENIES authority (§5.3.2 step 5); once the DID holds no role it is meaningless, and a re-admitted same-DID member is a fresh admission that MUST NOT inherit a phantom suspension — a residual suspension would otherwise wrongly deny the re-admitted member a capability their new role grants.

Per-DID content-access and routing state owned outside the role state is likewise dropped at removal: the member's `read_exclusion_list` entry (§5.9), its access-key store entry (§9.17), its MLS sequence counter, and its pseudonym routing entry (§9.10.4). The MLS group leaf for the removed DID is evicted by the MLS commit that precedes the state teardown; eviction is the cryptographic boundary and is non-negotiable — the state teardown described here is the bookkeeping that MUST converge with it, never a substitute for it.

Dropping the suspended-capability set on removal is a pure narrowing-side hygiene that never widens authority, consistent with the suspension-pruning rule at ceiling-change activation (§5.3.2 step 5): a suspension referencing a capability the member no longer holds is already droppable, and a removed member holds none. The runtime executes this teardown through the shared `ContextRoleState` removal primitive, clearing the four per-DID role fields together — so a context's **role state** is byte-identical after a remove-then-readmit of the same DID. Out-of-role per-DID state (read-exclusion entry, access-key store entry, MLS sequence counter, pseudonym routing entry) is dropped by whichever layer owns it, in the same operation.

## 5.7 Metadata

Context metadata follows a two-tier visibility model that balances legibility (informed consent before joining) with privacy (operational details that may be sensitive).

**Structural fields** (always visible — required for informed consent):

- Template ID, if created from a well-known template (§5.12)
- Capability ceiling and ceiling policy (`immutable` or `governed`, §5.3)
- Available roles and their permission sets
- Governance model
- Automated consequence rules and the `allow_automatic_access_revocation` opt-in, if declared (§7.3.7) — creation-time, member-enforced authority. §7.3.7 requires consequence rules to be visible before opt-in: hiding the automatic penalties of participation would undermine informed consent. For invited joiners these are additionally authenticated by the `InvitationBundle` signature over the full genesis `ContextParams` (§5.12.3.1).
- TTL / time-to-live, if set (§5.10)
- Promotion policy (`no_promotion` or `promotable`), if context has a TTL (§5.10)
- Memory scope (§5.11)
- Context mode (`Encrypted` or `Broadcast`, §5.14)
- Agent policy — `agent_keys_allowed`, `agent_rate_limit`, and `agent_cosign_required` (§4.9.3). A prospective member decides whether to join partly on whether the context admits their agent at all and on which of their agent's actions need a human signature, so the protocol makes these three parameters visible before joining rather than after. `ContextParams` declares none of the three today and no metadata projection carries them; stories SCP-AB-028, SCP-AB-030, and SCP-AB-031 of `.docs/prds/agent-binding.json` add the fields and SCP-AB-032 adds this projection, and §4.9.3 states what a reader may not assume until they land.
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
- Active outlet interface count (inbound and outbound, §6.2, §9.2.1)
- For child contexts (§5.13): parent context IDs, parent metadata summaries, parent governance configuration, and the prospective member's eligibility basis (§5.13.6)

Each operational field has a visibility of `PreJoin` (visible to anyone with the context_id) or `MemberOnly` (visible only to context members). The `MetadataVisibilityPolicy` is declared at context creation and follows the context's ceiling policy — immutable or governed via `ModifyCeiling`.

**Authentication is orthogonal to visibility.** The visibility split above governs *disclosure* — which fields a prospective member may SEE before joining. It does NOT govern *authentication* — whether the value a member enforces is creator-signed. A `MemberOnly` field is still creator-signed: for invited joiners the signature rides inside the HPKE-encrypted `InvitationBundle` (§5.12.3.1), delivered to an invitee who is about to become a member, so disclosing and authenticating a `MemberOnly` field to that specific invitee is consistent with the consent/privacy model — the creator chose the invitee and encrypted the bundle to them alone. This is why the §5.12.3.1 signature can authenticate the full genesis `ContextParams` — including `MemberOnly`-visible authority such as `economic_policy` (whose payee, per the operational visibility policy above, may be hidden from non-invited prospective members) — without weakening the pre-join disclosure limits that still apply to the *published* metadata record (§5.7.1).

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

Contexts publish their parameters to a metadata routing address that authorized parties can derive, enabling pre-join inspection per the legibility principle (§1). The address uses a keyed construction (§9.10.4.B) so it is NOT publicly derivable from the context ID alone — preventing context enumeration — while remaining derivable by members and authorized prospective members who hold the context's `context_metadata_key`:

```
metadata_routing_id = HMAC-SHA256(context_metadata_key, context_id || "scp-metadata-v2")
```

Published metadata includes structural fields (always) and operational fields filtered by `MetadataVisibilityPolicy`. Fields with `MemberOnly` visibility are omitted from the published metadata record. Members retrieve full metadata through the context's internal state, not the public metadata record.

Prospective members retrieve context parameters by subscribing to the `metadata_routing_id` on the relay without joining the context. The metadata record is signed by a current context admin, enabling verification of authenticity without membership. This makes the legibility guarantee mechanical for authorized parties: any holder of the `context_metadata_key` can derive the metadata address and inspect the context's visible parameters before deciding whether to join. The `context_metadata_key` is distributed per §9.10.4.B — generated at context creation, included (encrypted) in invitations, and published in the context entry for discoverable contexts. Non-discoverable contexts keep the key private, so their existence and metadata are not enumerable by parties who merely know or guess the context ID.

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

**One DID, one vote.** A human and their agent share one DID and one membership entry (§5.6), so a context counts one vote per member DID whichever verification method signed the ballot. An `#agent`-signed vote and an `#active`-signed vote from the same DID are the same member's vote: the single-vote dedup guard runs before signature verification, so a second vote from that DID is rejected as `AlreadyVoted` whichever key signed it. A member changes a cast vote by withdrawing it first, on the engines that support withdrawal.

**Category C — governance sets the context's agent restrictions.** A context restricts what an agent may do inside it through `agent_keys_allowed`, an agent-restricted role, `agent_rate_limit`, and `agent_cosign_required` (§4.9.3). Each one is a context parameter or a role that the context's governance model sets at creation and changes afterward through the same propose/approve path it uses for any other parameter — ADR-039 introduces no governance primitive for them. A change to any of the three `ContextParams` fields is a metadata change and is subject to the `metadata:edit` capability (§5.3.1); a change to an agent-restricted role assignment is subject to `role:assign`. Because all three parameters are structural metadata (§5.7), every member sees the current values, and a member who joined under the old values sees the new ones the moment governance executes the change. No shipped governance proposal type carries any of the four changes; stories SCP-AB-028 through SCP-AB-033 and SCP-AB-036 of `.docs/prds/agent-binding.json` deliver them, and §4.9.3 states what a reader may not assume until they land.

**Governance execution invariants.** When the runtime executes an approved governance action, two protocol-level invariants MUST hold:

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
| `registered_outlets` | 256 per context | Outlets are heavyweight registrations; 256 exceeds any practical context |
| `outlet_interfaces` | 256 per context | Cross-context interfaces are bilateral agreements; 256 exceeds any practical context |
| `threshold_signers` | 64 per context | Signers participate in quorum; >64 is operationally impractical |
| `suspended_capabilities[did]` | No artificial cap | Naturally bounded by ceiling cardinality — at most one entry per capability per member |
| `read_exclusion_list` | No artificial cap | Naturally bounded by membership count — cannot exclude non-members from CEK wrapping |
| `agent_cosign_required` | No artificial cap | Naturally bounded by ceiling cardinality — §4.9.3 makes every write path reject an out-of-ceiling entry and a repeated entry, so the list holds at most one entry per ceiling capability |

Both `suspended_capabilities[did]` and the removed DID's `read_exclusion_list` entry are dropped when the member is removed from the context (§5.6.1 — member removal is a clean teardown), so neither retains entries for non-members.

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

**Leaf convergence.** The `TTLExtended` leaf must be byte-identical across every member that records it, or their event-log Merkle roots diverge. Every field is therefore a convergent quantity: the old/new deadlines and the (lexicographically sorted) consenting-members list are convergent by construction; the leaf's own `timestamp` field is the committer-assigned proposal instant for the governance path, and — for the bilateral shortcut, which has no signed governance proposal — the convergent **pre-extension deadline** (the old deadline), NOT a per-member wall-clock `now()`. (This is a convergence key only; the TTL deadline is always derived from the leaf's `new_deadline_unix` payload field, never from the leaf `timestamp`. See ADR-049 §9, the single-source TTL-deadline invariant.)

## 5.11 Memory Scope

Contexts gain a declared memory scope — what happens to the context's data when it closes or expires. Memory scope is set at creation and visible in context metadata (visible before opt-in).

Three scopes:

**Ephemeral.** Context encryption keys are destroyed on close AND the SDK issues deletion requests to relays for all encrypted event data associated with the context. Content is physically unreadable (keys destroyed) and actively cleaned up (ciphertext deleted where relays comply). Durable metadata persists: who participated, when, the declared purpose, participation contributions (participation counts, outlet invocations), and discovery provenance. An agent's local orchestration (above the protocol boundary) may retain information from the interaction, but any data the agent subsequently uses elsewhere carries provenance at the protocol level: "sourced from closed ephemeral context."

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

**Summary.** Context produces a structured summary on close. Full content is destroyed (keys destroyed as with ephemeral). The summary persists with full provenance. Both parties can verify the summary against the event log before keys are destroyed. The summary format is defined by the context (via outlets or governance), not by the protocol — the protocol provides the lifecycle hooks (pre-close summary generation, verification window, key destruction) but does not prescribe summary content.

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
- **Read-only semantics:** No new messages, outlet invocations, or governance actions (except `ProposeContextMigration` cancellation) are accepted. Members can still read existing content and retrieve history.
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

Context creation requires specifying a ceiling, roles, governance model, memory scope, TTL, and outlets. For durable, bespoke contexts this is appropriate — the creator is designing a space. But contexts must also be cheap and disposable. If "spin up a quick context" requires manual configuration of six parameters, agents will route around the protocol for lightweight coordination. Context templates solve this.

### 5.12.1 Well-Known Templates

The protocol defines a set of well-known templates — named parameter bundles with fixed, predictable configurations. Templates are protocol-level identifiers, not SDK convenience wrappers. Both the creator and the joining party recognize the template ID and know exactly what it means without inspecting individual parameters.

```
Template: "scp:template/bilateral-ephemeral"
  ceiling:     [messages:read, messages:write, member:ban]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: ephemeral
  ttl:         required (creator sets duration, no default — forces intentionality)
  outlets:       none
  metadata_visibility: { member_count: MemberOnly, context_age: MemberOnly, creator_identity: MemberOnly, name: PreJoin, description: MemberOnly, economic_policy: MemberOnly, outlet_interface_count: MemberOnly, child_context_info: MemberOnly }

Template: "scp:template/bilateral-persistent"
  ceiling:     [messages:read, messages:write, member:ban]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: full
  ttl:         none
  outlets:       none
  metadata_visibility: { member_count: MemberOnly, context_age: MemberOnly, creator_identity: MemberOnly, name: PreJoin, description: MemberOnly, economic_policy: MemberOnly, outlet_interface_count: MemberOnly, child_context_info: MemberOnly }

Template: "scp:template/coordination"
  ceiling:     [messages:read, messages:write, outlet:query:*, outlet:call:*, member:ban]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: summary
  ttl:         required (creator sets duration)
  outlets:       creator-defined at creation
  metadata_visibility: { member_count: MemberOnly, context_age: MemberOnly, creator_identity: MemberOnly, name: PreJoin, description: MemberOnly, economic_policy: MemberOnly, outlet_interface_count: MemberOnly, child_context_info: MemberOnly }

Template: "scp:template/group-discussion"
  ceiling:     [messages:read, messages:write, member:invite, member:ban]
  roles:       [admin, member, observer]
  governance:  single-admin
  memory_scope: full
  ttl:         optional
  outlets:       none
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
  outlets:         creator-defined at creation
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
  | known_did(list)   // explicit operator allowlist — the only auto-accept trigger
```

> **Provenance (spec leads code, 2026-06-24).** The reference implementation's `TrustRequirement` (`scp-protocol` `context::policy`) currently still carries `Any` (accept from *any* identity) and `SharedContext` (co-membership) variants alongside the allowlist (`Explicit(Vec<DID>)`), and never implemented the prior `discovery_context` arm — a spec/code divergence predating this change. The allowlist (`Explicit(Vec<DID>)`, **renamed to `KnownDid` to match the spec's `known_did`** in the downstream code-correctness PR) is the sole surviving auto-accept trigger; `Any` and `SharedContext` are removed in the downstream code-correctness PR at the `scp-protocol` `context::policy` enum (+ `invitation.rs` `satisfies_trust`) — the single trust-policy evaluation site in the engine. Removing `Any` — a silent accept-from-*any*-identity **option** (it is an opt-in misconfiguration, not a system default — the system default is no-policy ⇒ prompt) — is a security fix. No code is changed in this spec-only change.

Example policy: "Auto-accept `bilateral-ephemeral` contexts from any DID on my allowlist, if TTL ≤ 10 minutes, at most 5 per hour."

**Security properties:**
- Policies never auto-accept contexts with outlet-invocation capabilities (ceiling containing `outlet:query:*` or `outlet:call:*`). Outlet access always requires explicit confirmation. This is non-overridable.
- Rate limiting prevents a compromised contact from flooding auto-accepts.
- **Auto-accept is allowlist-only.** The sole auto-accept trigger is a DID on the operator's explicit `known_did` allowlist. Co-membership in a shared context and registration/discoverability in an open registry are **NOT** trust signals and never trigger auto-accept: inferring trust from either is unsound, and discovery is how strangers *reach* you, not whom you auto-trust (consistent with §09's "from a known DID"). The allowlist has **no self-clear path** — the candidate cannot add itself to the evaluating party's allowlist; allowlist membership is set by the evaluator, not the candidate.
- **No-default auto-accept (normative).** There is **NO** default auto-accept policy. Absent an explicit, human-configured `AutoAcceptPolicy`, every invitation prompts the human (default-deny).
- Auto-accept policies are enforced in the SDK, not the protocol. The protocol sees a normal context join. The policy just determines whether the SDK prompts the human or acts autonomously.

**No auto-accept for outlet-bearing contexts.** This is a hard rule, not a default. Any context whose ceiling includes `outlet:query:*`, `outlet:call:*`, `outlet:query:{outlet_id}`, `outlet:call:{outlet_id}`, or any outlet-related capability requires explicit human or agent confirmation regardless of auto-accept policies. The rationale: outlet access is the capability that enables cross-context data flow (§6.2). Auto-accepting it would silently expand the agent's cross-context attack surface.

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
  outlets: [],
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
  context_params:     ContextParams       // The FULL genesis ContextParams the joiner installs
                                          // authority from: governance, ceiling, ceiling_policy,
                                          // roles, mode, ttl, memory_scope, economic_policy
                                          // (including payee), consequence_rules and the
                                          // allow_automatic_access_revocation opt-in, outlets, and
                                          // every other authority-relevant field. This is the
                                          // authenticated authority source (see Signature scope);
                                          // the joiner enforces from it, never from the lossy
                                          // metadata_snapshot.
  metadata_snapshot:  MetadataSnapshot    // Visibility-filtered VIEW for auto-accept policy
                                          // evaluation (§5.12.2) and display. Its structural
                                          // fields are derived from context_params and MUST agree
                                          // with them; its operational fields carry runtime state
                                          // (member count, age, name) not present in context_params.
  signature:          Ed25519Signature    // Creator signs all fields above (see Signature scope).
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

**Signature scope.** The creator signs `SHA-256("SCP-INVITATION-BUNDLE-V1:" || context_id || creator_did || relay_urls_hash || welcome_message_hash || key_material_hash || genesis_params_hash || metadata_snapshot_hash)`. The raw `context_id` and `creator_did` are encoded per the §9.5.1 length-prefixed rules (4-byte big-endian length prefix followed by UTF-8 bytes). Each `_hash` is the 32-byte SHA-256 output `SHA-256(canonical_json_jcs(field))` over the corresponding field — RFC 8785 (JCS) canonical JSON — inserted raw into the preimage (a fixed 32-byte value carries no length prefix, per §9.5.1). In particular `genesis_params_hash = SHA-256(canonical_json_jcs(context_params))` binds the **complete genesis `ContextParams`** into the signature, so the signature authenticates the full authority the joiner enforces — governance, ceiling, ceiling_policy, roles, mode, ttl, memory_scope, economic_policy (including payee), consequence_rules and the `allow_automatic_access_revocation` opt-in, outlets, and every other authority-relevant field — not merely the lossy `metadata_snapshot` (which omits economic-policy detail and consequence rules). `metadata_snapshot_hash` remains signed so the display / auto-accept view cannot be tampered independently of the authority it must agree with. The signature uses the creator's Active Signing Key (`#active`).

**Canonicalization rationale.** Per-field hashes use RFC 8785 canonical JSON (JCS), matching the cross-implementation canonical-hashing mandate in §9.5 (§09-security-model.md) and the §5.13.3 `0xFF02` extension precedent. MessagePack has no canonical form standard — field ordering varies by library, so it cannot guarantee byte-identical output across independent SDK implementations; JCS provides a formal canonicalization standard that can. This ensures two implementations that serialize the same logical field produce identical signed bytes and therefore verify each other's signatures. (The bundle's MessagePack transport envelope is unaffected: the signed preimage is built from JCS field hashes, not from the MessagePack envelope bytes, so the transport encoding never enters the signature.)

**Validation.** The invitee verifies the bundle before processing:
1. Resolve `creator_did` and verify `signature` against the creator's `#active` public key.
2. Verify `metadata_snapshot.structural` is consistent with `context_params`. Both are inside the same creator signature, so a divergence is a signed self-contradiction — reject. This blocks a creator from displaying benign structural values for the auto-accept check while enforcing hostile ones.
3. Validate the structural authority (`metadata_snapshot.structural`, equivalently the corresponding `context_params` fields) against the invitee's auto-accept policy (§5.12.2).
4. For the fields the `0xFF02` MLS group-context extension commits (the genesis `creator_did`, governance, ceiling, ceiling_policy, mode, parent lineage — §5.13.3), verify `context_params` and `creator_did` match the committed extension carried in `welcome_message`. In particular, the bundle's `creator_did` MUST equal the committed genesis `creator_did` (§5.13.3 rule 8): the bundle signature alone proves only that the SIGNER authored the bundle, not that the signer is the group's real creator/admin — an in-context member could sign a bundle naming an arbitrary `creator_did`, which is why the creator identity is anchored in the MLS-committed extension, not the signature. Authority for those fields is anchored in the MLS-committed extension; the bundle signature additionally authenticates the remaining genesis params (roles, ttl, memory_scope, economic_policy, consequence_rules, outlets) that `0xFF02` does not commit.
5. If accepted, install authority from the verified `context_params` and process `welcome_message` via MLS to join the group (Encrypted contexts) or initialize subscriber state (Broadcast contexts).
6. Use `context_metadata_key` to derive the metadata routing ID for ongoing metadata retrieval.

**HPKE encryption.** The serialized `InvitationBundle` (and, symmetrically, the `JoinResponse` of §5.12.3.2) is encrypted to the recipient with HPKE Base mode (RFC 9180) using the SCP HPKE suite (§9.5): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. The recipient X25519 public key is derived from their Ed25519 identity key via RFC 7748 birational mapping. The HPKE `info` and `aad` parameters are:

```
info = "scp-invitation-v1" || len(context_id) || context_id || len(creator_did) || creator_did
aad  = "scp-invitation-aad-v1" || len(context_id) || context_id || len(creator_did) || creator_did
```

Where `context_id` and `creator_did` are UTF-8 bytes, each preceded by a 4-byte big-endian unsigned length prefix (`len(...)`) per the §9.5.1 encoding rules. The wire output is `(enc, ct)` where `enc` is the 32-byte HPKE encapsulated key and `ct` is the AEAD ciphertext-and-tag — the RFC 9180 KEM context binds `enc` into the key schedule (`kem_context = enc || pkRm`, RFC 9180 §4.1), so `enc` is NOT additionally carried in `aad`. The `"scp-invitation-v1"` / `"scp-invitation-aad-v1"` domain separators are distinct from sender-key (`"scp-sender-key-v1"`), access-key (`"scp-access-key-v1"`), broadcast-key (`"scp-broadcast-key-v1"`), and private-state (`"scp-private-state-v1"`) HPKE strings.

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
      └── channel.send("sync on project?")   [send, 1 hop; the creator/initiator
                                              side sends immediately, but a
                                              Welcome-joined replica (the peer) can
                                              DECRYPT yet cannot SEND until the
                                              Phase-2E spawn-from-Welcome entrypoint
                                              lands — §5.15.8 Known-limitation /
                                              ADR-049 §Follow-ups #1]

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

Contexts can have parent-child relationships. A child context is a full context — its own MLS group, event log, governance, roles, outlets, ceiling, and membership — that is structurally and cryptographically linked to one or more parent contexts. The parent relationship constrains the child (ceiling inheritance, lifecycle coupling, membership eligibility), is visible in metadata, and is bound into the child's MLS group identity so that lineage cannot be forged or rewritten after creation.

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

Coordination uses an intrinsic outlet call available within each context's governance. Alice invokes the child-creation outlet in A with the proposed child params and the list of co-parents. A's governance evaluates and, if approved, publishes a **child creation proposal** — a signed, content-addressed record of the approved params. Bob does the same in B. The protocol matches proposals by their content hash: when all proposed parents have published matching proposals (identical child params), the child is created.

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
Alice (in A) → invokes child creation outlet → A's governance approves
             → A publishes proposal { match_hash, parent_list, approval_sig }
Bob (in B)   → invokes child creation outlet → B's governance approves
             → B publishes proposal { match_hash, parent_list, approval_sig }
SDK observes matching proposals from all parents
→ Child C created
→ Both Alice and Bob are initial members
```

This reuses the existing outlet call model — no new protocol primitive. The child creation outlet is intrinsic to contexts that include the `context:child:createCreate` capability in their ceiling.

**C. Member proposal without creation rights.** Alice is in A but her role doesn't include creation rights. She proposes the child through A's governance (§5.9). A's governance evaluates and either approves or rejects the proposal. If approved, the governance itself authorizes the creation on A's behalf. Same process on B's side.

**Creation protocol:**

1. **Initiator constructs child params:** ceiling (must be ≤ intersection of parent ceilings), governance model, roles, TTL (must be ≤ minimum parent TTL if parents have TTLs), memory scope, outlets, and the parent governance configuration (§5.13.4).
2. **Governance proposal sent to each parent.** The proposal includes the full child params plus the list of all proposed parents. Each parent's governance evaluates independently.
3. **All parents approve.** The child context is created. Creation is logged in every parent's event log and in the child's event log.
4. **Any parent rejects.** Creation fails. No child is created. The rejection is not logged (the proposal never materialized).

**Cryptographic binding.** When the child's MLS group is initialized (step 3), the parent context IDs and the content hash of the parent governance configuration are included in the MLS `group_context` extensions field. This makes the parent lineage part of the child's cryptographic group identity — the `group_id` derived from the `group_context` is a function of the parent references. Consequences:

- **Lineage is unforgeable.** Claiming different parents after creation would require creating a new MLS group with a different `group_id`. Any member can verify the parent lineage by inspecting the `group_context` extensions — no trust in metadata required.
- **Two independent verification paths.** The parent relationship is recorded in both the MLS `group_context` (cryptographic, part of the group identity) and the event log (Merkle tree, signed entries). Both would need to be compromised to forge lineage.
- **Governance config is tamper-evident.** The content hash of the `ParentGovernanceConfig` in the `group_context` means any discrepancy between the claimed governance configuration and the cryptographically committed one is detectable.

**MLS group_context extension format.** SCP defines a custom MLS extension for carrying context parameters in the `group_context`. The extension uses the IANA private-use range for MLS extension types:

```
Extension Type ID: 0xFF02 (SCP Context Parameters)

ExtensionType: 0xFF02
ExtensionData: RFC 8785 (JCS) canonical-JSON-serialized ScpContextExtension

ScpContextExtension {
    context_id:               ContextId,           // The SCP context ID
    creator_did:              DID,                  // The group's genesis creator/admin DID
    context_mode:             u8,                   // 0 = Encrypted, 1 = Broadcast
    governance_policy_hash:   [u8; 32],            // SHA-256 of canonical_json_jcs(governance_policy)
    ceiling_policy:           u8,                   // 0 = Immutable, 1 = Governed
    ceiling_hash:             [u8; 32],            // SHA-256 of canonical_json_jcs(capability_ceiling)
    parent_context_ids:       Vec<ContextId>,       // Sorted lexicographically; empty for root contexts
    parent_governance_hash:   Option<[u8; 32]>,    // SHA-256 of canonical_json_jcs(parent_governance_configs); None for root contexts
}
```

**Serialization.** The `ScpContextExtension` is serialized using RFC 8785 canonical JSON (JCS), matching the cross-implementation canonical-hashing mandate in §9.5 (§09-security-model.md). MessagePack has no canonical form standard — field ordering varies by library, so it cannot guarantee byte-identical output across implementations; JCS provides a formal canonicalization standard that can. This ensures that independent implementations produce identical byte representations for the same extension contents.

**Extension type ID.** `0xFF02` is in the IANA private-use range for MLS extension types (`0xFF00`-`0xFFFF`), as defined in RFC 9420 Section 17.3. If SCP registers with IANA in the future, the extension type ID will transition to an assigned value. SDKs MUST accept both the private-use ID and any future assigned ID during a transition period.

**Validation rules:**

1. The `ScpContextExtension` with type ID `0xFF02` MUST be present in the `group_context.extensions` of every SCP MLS group. MLS groups without this extension are not SCP contexts and MUST be rejected.
2. The `context_id` in the extension MUST match the context ID in the context's metadata and event log.
3. The `governance_policy_hash` MUST match `SHA-256(canonical_json_jcs(governance_policy))` computed from the context's declared governance policy.
4. The `ceiling_hash` MUST match `SHA-256(canonical_json_jcs(capability_ceiling))` computed from the context's declared capability ceiling.
5. For child contexts: `parent_context_ids` MUST be non-empty and sorted lexicographically. `parent_governance_hash` MUST be present and match `SHA-256(canonical_json_jcs(parent_governance_configs))`.
6. For root contexts: `parent_context_ids` MUST be empty. `parent_governance_hash` MUST be `None`.
7. Any mismatch between the extension contents and the context's metadata is a protocol violation. The SDK MUST reject the MLS group and report the discrepancy.
8. The `creator_did` in the extension MUST match the `creator_did` the joiner is asked to install as the context's creator/admin — the bundle's `creator_did` on a Welcome-based join (§5.12.3), or the snapshot's `role_state.creator_did` on import/restore. A mismatch means the presented creator is not the party the group cryptographically committed at creation; the SDK MUST reject the MLS group **before** installing any authority (governance engine, admin set) for that creator. This binding pins the **genesis** creator (the initial `SingleAdmin` admin); admin *transfers* are not tracked in `0xFF02` — they apply from the authenticated event log after join. This rule is the sole cryptographic anchor of admin identity for DID-less governance models (e.g. `SingleAdmin`, whose `governance_policy_hash` is a constant and therefore commits no identity): without it, an in-context member could sign an otherwise-valid invitation bundle naming an arbitrary `creator_did` and have the joiner install that party as admin.

**Implementation status.** This extension is implemented end-to-end. The creator writes the `0xFF02` extension into the MLS `group_context` at group creation, and KeyPackages declare support for it; it is carried unmodified through the Welcome and subsequent Commits as part of the group's committed cryptographic identity. On join (Welcome processing) and on import/restore, the joiner reads the group's committed extension and verifies the caller-supplied (or snapshot) context parameters AND the presented `creator_did` against it per the validation rules above before installing any crypto state or authority — a group presenting no `0xFF02` extension (rule 1), one whose contents diverge from the consented parameters, or one whose committed genesis `creator_did` differs from the `creator_did` the joiner is asked to install as admin (rule 8), is rejected before any governance engine or admin set is built. Authority — including the identity of the creator/admin — is therefore derived from the cryptographically committed extension, never from unverified caller-supplied parameters or an unverified bundle-asserted creator.

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
    | outletRegistration           // New outlets added to child
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
                   requires_approval_for: [outletRegistration], on_sever: .cascade_close }
// A can shut down the relationship. B controls the outlets (it's the service provider).
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

This means a member evaluating whether to join a child sees: "This is a child of contexts A and B. A has 30 members, single-admin governance, ceiling [msg, outlets]. B has 15 members, multi-sig governance, ceiling [msg]. The child's ceiling is [msg]. Parent A can close the child unilaterally. Parent B cannot. If A severs, members from A only are evicted."

Full legibility before opt-in applies to nesting relationships the same as everything else in the protocol. No hidden parent governance. No undisclosed co-parents.

### 5.13.7 Interaction with Other Mechanisms

**Templates.** Well-known templates (§5.12.1) can be used for child contexts. The template constrains the child's params as usual; the parent relationship adds the ceiling intersection and lifecycle coupling on top. A child created from `bilateral-ephemeral` with two parents is an ephemeral bridge — TTL'd, keys destroyed on close, ceiling ≤ intersection.

**Standing contexts.** A standing context (§5.12.6) between Alice and Bob can be modeled as a multi-parent child of whatever context(s) Alice and Bob share. This is not required — standing contexts remain lightweight bilateral contexts that work without nesting. But if structural governance over the standing context is desired (a parent context's governance should have authority over the channel), nesting provides that.

**Outlet interfaces.** Outlet interfaces (§6.2) and multi-parent children serve different purposes and coexist:

| | Outlet interface | Multi-parent child |
|---|---|---|
| Relationship | Asymmetric (caller/outlet) | Symmetric (peers) |
| Data flow | Structured (schema-declared) | Full context (messages, outlets, everything) |
| Governance | Both contexts govern each call | Configured at creation, child self-governs |
| Duration | Per-call (or per-session) | Persistent (until closed or TTL) |
| Use case | Service calls, data queries | Collaboration, negotiation, ongoing peer interaction |

A context might use both: outlet interfaces for structured service queries and a multi-parent child for ongoing collaboration with the same counterpart.

**Provenance.** Data originating in a child context carries provenance (§7.7) that includes the child's parent lineage. When data from a child crosses another context boundary (via outlet interface or further nesting), the provenance chain includes the child and its parents. This makes the trust basis structurally legible: "this data came from a child of A and B" tells the receiver more than "this data came from some context."

**Auto-accept and child contexts.** Child-context eligibility (§5.13.2) is a cryptographically-enforced **floor** on *who can reach you* with a child invitation — a child can only be offered by a context you are already a verified member of (relay-enforced, §5.13.2), not an SDK honor system. It is **not** a trust signal and does **not** trigger auto-accept. Auto-accepting a child invitation follows the same §5.12.2 rule as any other context: the inviter's DID MUST be on the operator's `known_did` allowlist, with the ceiling/TTL caps the policy specifies; otherwise the invitation prompts the human (default-deny). Co-membership in a parent is the floor that lets the invitation reach you, never a substitute for the allowlist.

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
info = "scp-broadcast-key-v1" || len(context_id) || context_id || len(author_did) || author_did || epoch_bytes
aad  = len(context_id) || context_id || len(author_did) || author_did || epoch_bytes
```

Where `context_id` and `author_did` are UTF-8 bytes, each preceded by a 4-byte big-endian unsigned length prefix (`len(...)`) per the §9.5.1 encoding rules, and `epoch_bytes` is the 8-byte big-endian encoding of the broadcast key epoch (fixed-width, no length prefix needed). The length prefixes prevent boundary-shift ambiguity, where a `context_id` suffix could masquerade as an `author_did` prefix — matching the sender-key (§9.16.2) and access-key (§9.17.1) `info`/`aad` constructions. The `"scp-broadcast-key-v1"` domain separator is distinct from `"scp-sender-key-v1"` (encrypted contexts) and `"scp-access-key-v1"` (content access keys), preventing cross-protocol key confusion. The three domain separators ensure that an HPKE ciphertext produced in one protocol cannot be replayed in another — different `info` values produce different HPKE key schedules.

### 5.14.3 Subscriber Registration

Broadcast contexts reuse the two-tier membership model from contexts with discovery outlets (§6.2.2B):

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
- `provenance_hash = SHA-256(serialize(provenance))` if present, or `SHA-256(0x00)` if absent (same sentinel as InnerEnvelope, ADR-002). `serialize` is the canonical provenance encoding defined in §24.3.3: positional MessagePack (`rmp_serde::to_vec`) over the `DataProvenance` struct in declaration field order. This is the same encoding used for the event-log provenance-hash leaves, so the value is identical whether computed on the signed broadcast path or the event-log path.
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

A governance ban is recorded in a durable per-context ban record independent of the subscriber registry and of `read_exclusion_list`; it persists across the banned subject's own leave and across a subsequent `RemoveMember`, and is cleared ONLY by an authority via `RestoreAccess`. Consequently a banned DID cannot re-subscribe by leaving and replaying a retained `messages:read` UCAN.

Default template configuration: encrypted templates include `member:ban` in their ceiling by default (§5.12.1); broadcast templates do not. Broadcast contexts can add `member:ban` via explicit `ContextParams` at creation or via `ModifyCeiling` governance action if `CeilingPolicy::Governed`.

**Author removal.** Removing an author from a broadcast context (revoking their broadcast key and preventing future publishing) is a governance-gated action. Author removal uses `GovernanceAction::RevokeAccess { did, access: Write }` — the general content access revocation mechanism (§5.9, ADR-031). `RevokeAccess` with `access: Both` stops publishing AND suppresses historical content; `access: Write` stops future publishing only. There is no standalone API to remove an author without governance approval. This enforces the protocol tenet: "Agents are participants, not enforcers." When the governance proposal is approved and executed: the author's broadcast key is destroyed, `publish()` returns `PermissionDenied`, key requests for the author return `Deny`, and a `WriteAccessRevoked` event is emitted. Subscribers who cached the author's old key can still decrypt historical messages (unless `access: Both` was used, in which case access keys are also destroyed per §9.17).

**Sybil resistance.** Broadcast contexts are the primary target for Sybil block bypass because key requests travel as relay messages (not MLS application messages). The membership gate in `handle_sender_key_request` verifies that the requester is a registered subscriber before distributing keys. Identity-linked block expansion and group blocking further mitigate Sybil attacks. See §9.16.6 for the full mitigation specification.

**Durability (crash boundary).** A per-author block AND a governance ban are **authorization-downward** operations (§9.4.2): each advances the per-author broadcast key epoch and/or adds a DID to a block list, revoking future key access. They MUST be **sync-persisted fail-closed** — the block/ban is durable, atomically with the context's `read_exclusion_list`, BEFORE the operation is acknowledged and before any observer (the acking caller, the `KeyEpochAdvance` relay message, the `MemberBlocked`/`ReadAccessRevoked` event-log leaf) sees the effect. A crash in the write-coalescing window MUST NOT roll a completed block/ban back: rolling back a block re-grants a revoked subscriber post-block key access (a confidentiality break — encryption-as-access-control, §9.5). The serve side is defense-in-depth: `handle_key_request` MUST deny any requester present in `read_exclusion_list` with the uniform deny reason (block-status non-leakage above) before evaluating per-author block state, and a context restored from persistence MUST reconcile `read_exclusion_list` back into every author's block list and drop excluded DIDs from the registry. Because a per-author UNILATERAL block does NOT write `read_exclusion_list`, restore-reconciliation cannot rescue that arm — the per-author block's own fail-closed persist is load-bearing. The UNBLOCK / `RestoreAccess` direction (block-list REMOVE) is authorization-UPWARD and MAY be coalesced (best-effort): a coalesce-window rollback re-instates the block, the fail-safe direction. **Voluntary unsubscribe** with forward-secrecy key rotation is authorization-UPWARD-safe in the same way and is likewise coalesced (best-effort): it only advances the per-author key epoch forward — a coalesce-window rollback returns to "subscriber present under the old key", never a re-grant — so, like UNBLOCK, it is intentionally NOT part of the fail-closed revocation path and MUST NOT be mistaken for one. **Threat-model scope.** This crash-durability guarantee is only as strong as the confidentiality and integrity of the persisted `ContextSnapshot` at rest: it defends against a crash in the write-coalescing window, NOT against an attacker who surgically tampers with the persisted bytes — storage-at-rest confidentiality/integrity is a separate boundary (the encrypted-at-rest storage layer, §17) and out of scope for this clause. See §9.4.2 and ADR-049 §9 for the persistence-tier invariant.

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
2. **Contexts with discovery outlets.** Authors register broadcast contexts via `agent_register` in contexts with discovery outlets (§6.2.2B), with metadata indicating the context mode.
3. **`.well-known/scp`.** Operators MAY list broadcast contexts in their `.well-known/scp` document (§18.3). Only broadcast context IDs may be listed — encrypted context IDs MUST NOT appear (§9.10 metadata privacy).
4. **Out-of-band URI.** The universal context URI format (§18.4) is used for sharing context references: `scp://context/<context_id_hex>?relay=<url>&mode=broadcast`. The legacy format `scp://broadcast/<context_id_hex>?relay=<url>` is accepted as an alias and normalized to the universal format.

### 5.14.12 Security Model Delta

Relative to Encrypted contexts, Broadcast contexts have the following security property changes:

**Retained:** Ed25519 authentication, content integrity (content_hash + signature), provenance, non-repudiation, UCAN authorization, event log, human accountability.

**Changed:** Confidentiality via per-author broadcast key (not MLS). No MLS `membership_tag` (authentication is signature-only). No MLS forward secrecy (mitigated by key epoch rotation on block events). Public `routing_id` (SHA-256 of context_id, not HKDF-derived). Author identity visible to relays in the outer envelope (authors are public figures in a broadcast context — this is a feature, not a leak).

See §9.5, §9.8, §9.9, and §9.10 for the full broadcast security analysis.

**Broadcast scale-out is a transport-layer concern.** Fan-out to large audiences is achieved by relays/CDNs re-serving the already-public encrypted `BroadcastEnvelope` (§5.14.5) — no key delivery, grant, or saga is involved. There is no context-level "hosting" relationship: content cannot flow *through* an intermediate context to that context's members without a decrypt-then-re-encrypt stage, which violates context-isolation and encryption-as-access-control (§5.11A.6). A relay re-serving ciphertext grants no new access; only an entity that independently joins B as a §5.14.3 subscriber can read B's content.

## 5.15 Runtime Concurrency Model

SCP runtimes serialize all mutation of a single context's state through exactly one owning computation. Implementations MAY use any concurrency primitive that delivers the properties below; the reference implementation uses one actor task per context. Protocol observers may depend on these properties.

### 5.15.1 Single-Context Serialization

For any given context, operations execute in a total order. No two operations on the same context observe or mutate state concurrently. The total order is determined by the arrival order of operations at the context's owning computation.

Operations on different contexts are independent and MAY run in parallel, bounded only by the runtime's scheduling model.

Runtimes apply backpressure when a single context's operation queue grows unbounded. Implementations MUST provide a per-context queue with a finite bound of at least 256 operations; a deeper bound is permitted. Callers observe backpressure as a typed **context-busy** error (surfaced consistently across bindings; see each SDK's error taxonomy) and SHOULD retry with backoff.

Authorization-downward operations (see §9.4.2) MUST NOT be starved by coalesced or lower-priority traffic: either the queue is strict FIFO (so §9.4.2 sync-persist bounds remain time-bounded), or authorization-downward commands are processed at or above all other categories. Implementations choose; callers observe no weaker ordering than strict FIFO.

Among commands in the same priority class (including two authorization-downward operations on the same context, or an authorization-downward operation co-pending with a saga-phase message), arrival order is preserved. No reordering is permitted beyond the FIFO or strict-priority-lane-plus-FIFO shapes above; a conformant implementation never processes a later-arriving command of the same class before an earlier-arriving one of the same class.

### 5.15.2 Context State Variants

A context's state is mode-specific. An encrypted context carries MLS group state and sender keys; a broadcast context carries per-author broadcast keys, subscriber list, and author blocks.

**Mode invariant** (normative): mode is fixed at context creation; a context never changes mode over its lifetime. A mutation that would require changing mode MUST fail with a typed mode-mismatch error. This invariant is protocol-level, not concurrency-level; it is restated here because the actor-per-context model relies on it (one actor, one mode-specific state shape).

### 5.15.3 Caller-Visible Persistence Guarantee

**Observers** (used throughout §5.15, §9.4.2, §17.15): for the purposes of persistence-ordering guarantees, any of the following counts as an observer of a mutation and MUST NOT see the effect before the persist tier's guarantee completes — the caller's acknowledgment, an outgoing network message derived from the mutation, a readable event log entry, an event-log subscriber notification, a sync-tier replication stream, or a saga phase message sent to another actor. Additional observer channels a specific implementation introduces (e.g., a custom RPC stream) MUST be treated equivalently.

Operations fall into two persistence tiers.

**Sync-persisted** — the caller's acknowledgment implies durable commit. A process crash immediately after the ack does not roll back the operation, and no observer (as defined above) sees the effect before the persist completes. Sync-persisted operations — this is the complete enumeration; §9.4.2 lists the subset that is a security invariant:

- MLS epoch advance, sender-key rotation, MLS member removal
- Every authorization-downward operation enumerated in §9.4.2
- Event log append (chain integrity)
- Saga phase transitions and per-actor saga-state transitions (§5.15.4)
- KeyPackage consumption (Welcome idempotency)

**Coalesced-persisted** — state MAY be persisted up to 50 ms after mutation. A process crash within this window rolls state back to the last persisted snapshot. Implementations MAY persist more aggressively but MUST NOT coalesce beyond 50 ms. The bound is observable via crash-recovery conformance tests: after sustained mutation at any rate, at most 50 ms of mutation may be absent from the post-recovery snapshot.

Coalesced rollback applies to: participation counters, velocity trackers, incremental cache updates, in-flight send-sequence assignments. Send-sequence monotonicity is preserved across rollback by the reservation protocol in §5.15.7.

The security invariant governing which operations belong in the sync-persisted tier is stated in §9.4.2.

### 5.15.4 Cross-Context Operations Use Sagas

Operations spanning **2+ distinct** contexts — currently just cross-context outlet invocation (§6.2.4) — execute as coordinated sagas driven by a supervisor that never allows contexts to await each other directly. (Standing-pair creation, §5.15.8, is **not** a saga: a standing pair is one MLS context with two members, so it is single-context async creation synchronized by MLS + the event-log consistency layer, with no cross-context atomicity to coordinate.) Phase states and the predicates that select among their outgoing transitions:

```
Initiated --[supervisor begins Prepare]--> PreparingA
PreparingA --[A returns Prepared]--> PreparingB
PreparingA --[A returns Rejected | Prepare timeout]--> Aborting
PreparingB --[B returns Prepared]--> Committing
PreparingB --[B returns Rejected | Prepare timeout]--> Aborting
Committing --[both actors return Committed]--> Committed (terminal)
Committing --[retry budget exhausted]--> NeedsRepair (terminal)
Aborting   --[all participants ack Abort]--> Aborted (terminal)
```

Each phase transition is synchronously persisted to a durable journal (§17.16) before any outbound effect of that phase — including the phase message dispatched to the next participating actor — is visible. Journal durability is the gate; the subsequent phase message and any other observer channel (§5.15.3) follow after the journal's durable acknowledgment. On process restart the supervisor replays unresolved journal entries.

Concurrent sagas are serialized at the granularity of their **participant context set**, not supervisor-wide. A saga reserves the set of contexts it spans (one `saga_pending` slot per context-actor); a second saga whose participant set is disjoint proceeds concurrently, while a second saga whose participant set **overlaps** — shares **at least one** context with — an in-flight saga is rejected with a typed **saga-busy** error (the contended context's slot is already held; surfaced consistently across bindings). Overlap is non-empty participant-set intersection: sharing a single context is sufficient to conflict, so two sagas that share only one common context (e.g. two cross-context outlet invocations that share a common target context) serialize at that shared context and never run concurrently. A `NeedsRepair` outcome **releases** the concurrency reservation: an operator action still resolves the divergence, but a stuck saga MUST NOT wedge unrelated sagas. (`NeedsRepair` is **FSM-terminal** — the automatic retry machine stops there, per the FSM above — but is **not a *resolved* state**: §17.16.1's unresolved-saga scan still loads it for crash-recovery and it is cleared only by operator repair or on the next process start (§17.16). An outlet-invoke divergence (§6.2.4) can therefore stay unresolved until then — which is exactly why the concurrency reservation is released the moment the saga reaches `NeedsRepair`, rather than held until resolution.)

Commit retry budget: three retries (500 ms / 1 s / 2 s delays), then terminal `NeedsRepair` requiring operator action or process restart. No indefinite retry loop.

There is currently **no** secret-bearing saga; §9.4.3 stands as the contract any future secret-bearing saga MUST satisfy. The single saga — cross-context outlet invocation (§6.2.4) — is public-metadata-only: its journal and envelopes carry no bearer material (the outlet invocation carries a UCAN *index*, not the token). It marks resolution with `secret_bearing=false`, so no synchronous on-disk evidence overwrite is required. (Standing-pair creation is not a saga and journals nothing — §5.15.8.)

### 5.15.5 Governance is Single-Context

All governance actions in ADR-031 run single-context. Governance never requires cross-context coordination; if it appears to, that is a spec bug to be surfaced rather than a saga to be designed.

### 5.15.6 Identity Scope

Per-identity resources (KeyPackage pool, wrapping keys, recovery state) are owned at the identity level, not the context level. An operation executing against a context `X` held by identity `A` MAY read `A`'s per-identity state and MUST NOT read any other identity's per-identity state directly. Cross-identity *coordination spanning 2+ context-actors* executes as a saga (§5.15.4), though no current operation requires it: identity-key migration (the §9.12 Compromise Recovery Protocol / migration-proof flow) is a single-identity governance flow, not a saga, and cross-identity custody handover of context key material does not exist (it is a security violation under §5.11A.6 — encryption-as-access-control means access is gained by joining, never by receiving group state out-of-band).

### 5.15.7 Send-Sequence Reservation

An implementation that assigns monotonically increasing send-sequence numbers MUST guarantee that a sequence number becomes durable (consumed) if and only if the corresponding encrypted payload has been handed to the transport layer for transmission. Any terminal outcome prior to transmit — including encryption failure, caller-side cancellation, timeout, operation panic, or early error return — MUST release the sequence number back into the sequence pool.

The reference implementation uses an RAII reservation guard (drop-on-not-commit). Non-Rust reference implementations MUST use an equivalent mechanism that is robust against panic, exception propagation, and cancellation; language-specific `try/finally` approaches MUST cover every terminal path in the operation.

A receiver MAY observe gaps in the send-sequence of a peer (for example, a legitimate send-then-crash where transmission occurred but the acknowledgment was lost). Receivers MUST treat gaps as non-anomalous for the purpose of anti-replay: monotonic advancement of a high-water mark is the only requirement.

See ADR-049 for the reference-implementation mechanism and rejected alternatives.

### 5.15.8 Standing-Pair Creation (Single-Context Async)

A **standing pair** is the `bilateral-persistent` context two identities create on first contact (§5.12.6). It is **ONE** MLS context — one MLS group with **two members**, NOT two contexts: the symmetric derivation below has both parties compute the *identical* `derived_context_id`, so they create and join the **same** context and each member's node holds a **replica** of it. Replicas are kept consistent by **MLS** (epoch-ordered Commits + the bootstrapping Welcome) over the event-log RFC-6962 consistency layer (§17) — the same synchronization every single context uses. There is **no cross-context atomicity to coordinate**, so creating a standing pair is **ordinary single-context async creation**, *not* a cross-context saga.

**Normative contract (implementer summary).** The rest of this section is the threat-model justification; an implementer can build the path from this summary alone:
- **Derivation.** `derived_context_id = SHA-256("standing:" ‖ len32(did_lo)‖did_lo ‖ len32(did_hi)‖did_hi)` over the two §3.8.1-canonical DIDs sorted lexicographically (`len32` = 4-byte big-endian length prefix, §9.5.1). Both parties compute the identical id; no party "allocates" it.
- **Async flow (single context, no saga).** (1) Initiator creates a 1-leaf MLS group; (2) fetches the peer's published `KeyPackage` and `add_member`s the peer; (3) emits the **Welcome as an `InvitationBundle`** to the peer's invitations routing id, registers Active, and records the peer; (4) the peer **consent-gates on Welcome receipt**, in order: (a0) re-derive `derived_context_id` and reject on mismatch; (a) refuse if the initiator is block-listed (§3.7.1); (b) **allowlist-or-prompt** — auto-join ONLY if the initiator's DID is on the operator's `known_did` allowlist (§5.12.2), otherwise prompt the human (default-deny). See step-4 below for the full normative gate.
- **Ok-return contract.** `Ok` means the **initiator's replica is created and the Welcome dispatched** — it does **NOT** imply the peer joined. Offline / slow / blocking / declining peers all yield the identical `Ok` (no synchronous confirmation).
- **Send-gating caveat.** Any party that obtains its replica via Welcome-join can join and **decrypt** but **cannot SEND** until the Phase-2E spawn-from-Welcome entrypoint lands.

> **Provenance (correction, 2026-06-18; length-prefix adopted 2026-06-24).** §5.15.8 was previously specified as a two-phase-commit cross-context saga (originally authored as the standing-pair saga). That was a miscategorization: a 2-member MLS group is one context, replica sync is MLS + the event-log consistency layer, and a saga coordinates atomicity across **2+ distinct** contexts sharing no sync protocol — which a standing pair is not. The sole genuine cross-context saga is §6.2.4 (cross-context outlet invocation). See ADR-049 §3 / §3a / §3b. (The prior claim that unconditional length-prefix injectivity "would add no security" is **retracted**: the colon-join was always the sole structural isolation anchor for `derived_context_id`; the `group_id` removed in the saga-cut was the *saga's* separate MLS group identifier, not an isolation co-anchor.) **The length-prefix framing is now ADOPTED here (Alec 2026-06-24), not deferred:** the *Determinism precondition* derivation uses the §9.5.1 length-prefixed form, making injectivity unconditional and retiring the **colon-freedom method-admission dependence** (§3.8.1 RETAINS a method-admission gate for canonical *agreement* — what length-prefix retired is only the colon-freedom injectivity assumption) — see *Injectivity invariant* below. The code helper `derive_standing_context_digest` currently colon-joins and is updated to the length-prefixed form in the downstream standing-pair implementation PR; the spec leads here, and because the standing-pair creation path is not yet wired, there is **no live divergence** to reconcile.

**Determinism precondition.** The id is a pure function of the two DIDs, **length-prefixed** per the §9.5.1 variable-length-bytes rule:
```
derived_context_id   = SHA-256( "standing:" || len32(did_lo) || did_lo || len32(did_hi) || did_hi )
standing_context_id  = "standing-" || hex( derived_context_id )
```
where `len32(x)` is the 4-byte big-endian length prefix of `x` (the §9.5.1 variable-length-bytes encoding). `did_lo` / `did_hi` are the two participant DID strings, **each reduced to its canonical DID string form (§3.8.1)** before being sorted lexicographically (bytewise UTF-8). `hex(...)` is lowercase hex of the 32-byte digest; the raw 32-byte digest is `derived_context_id: [u8;32]`. Canonicalizing to the single per-method comparison form (§3.8.1) **before** the sort guarantees both parties feed byte-identical bytes into the preimage — neither can submit a divergent encoding of the same DID — so `derive(A,B) == derive(B,A)` and both compute the identical id; no party "allocates" it. The length-prefixed framing matches every other DID-pair hash in the protocol (§9.5.1); §3.8.1's canonicalization here is solely about both parties feeding **byte-identical** DID strings into the preimage, no longer about injectivity (which length-prefixing makes unconditional — see *Injectivity invariant*).

**Injectivity invariant (load-bearing, unconditional by construction).** The length-prefixed preimage `"standing:" ‖ len32(did_lo) ‖ did_lo ‖ len32(did_hi) ‖ did_hi` is injective **mechanically, for ANY DID method or grammar**: each `len32` prefix fixes its field boundary unambiguously, so the preimage re-parses **uniquely** back into the ordered pair `(did_lo, did_hi)` and no attacker can shift a boundary to forge a colliding pair — regardless of whether the method-specific id contains a raw `:`. The injectivity therefore **no longer depends** on the method-specific id being colon-free: length-prefixing **retires the colon-freedom method-admission dependence** (the prior colon-join framing required a colon-free method id; length-prefixing makes injectivity hold unconditionally). §3.8.1 still RETAINS a method-admission gate for canonical *agreement* (rejecting a method with no canonical string form); what length-prefix retired is the **colon-freedom injectivity assumption**, not that agreement gate. This matches every other DID-pair hash in the protocol (§9.5.1's variable-length-bytes rule). §3.8.1's role here is narrowed accordingly: it ensures both parties feed **byte-identical** DID strings (canonical agreement), not field-boundary disambiguation — that is now the `len32` prefixes' job.

**MLS-layer defense-in-depth.** The `create_mls_group` `Entry::Vacant` guard keys on `SHA-256("standing-" ‖ hex(derived_context_id))` (a 1:1 function of `derived_context_id`), rejecting a second **`create_mls_group`** under the same id per node (the convergence `join_from_welcome` is a *replace-not-create*, governed by the atomic in-place replacement under *Concurrent-creation collision resolution* below, not by this create-guard). A colliding id cannot occur in the first place (length-prefixed injectivity forecloses it by construction); were one to, MLS `GroupId` + per-group key schedule + per-member credentials (RFC 9420) are independent isolation barriers — **a collision alone grants no plaintext.**

**Roles (symmetric, normative).** There is **no creator/peer asymmetry in the common case**: either party MAY initiate (create a 1-leaf group, fetch the peer's published `KeyPackage`, `add_member`, emit the Welcome); when only one initiates, the other **joins on Welcome receipt** (consent permitting). The `did_lo` / `did_hi` tie-break governs **ONLY** the genuine simultaneous-create race below (the per-node `Entry::Vacant` guard cannot coordinate two distinct nodes), not a creator pin.

**Concurrent-creation collision resolution (normative).** After convergence **exactly one group survives per `derived_context_id`: `did_lo`'s**, by construction. The invariant: a node holding a self-created group under that id, upon a **freshly-joined** Welcome (its single-use KeyPackage init key still unconsumed, ADR-049 §9) whose creator is **cryptographically bound to `did_lo`** per §9.7.1, **joins, then destroys** its own group; **all other Welcomes are ignored**. Concretely:

- `did_lo`, receiving a `did_hi`-authored Welcome under an id where it already holds its own self-created group, **ignores** it — it builds no state from `did_hi`'s group, **so `did_hi`'s later destroy of that orphan equivocates against no peer** (`did_lo` having never observed it).
- `did_hi`, receiving a `did_lo`-authored Welcome under such an id, **joins `did_lo`'s and then destroys** its self-created group.

The bound-creator check (§9.7.1) requires **BOTH** the creator leaf's `ScpCredential.did == did_lo` **AND** the creator-leaf's **KeyPackage attestation** — binding the leaf's ephemeral MLS signature key to `did_lo`, signed by `did_lo`'s `#active`/`#agent` — to verify against a verification method in `did_lo`'s DID document (§9.7.1); a self-asserted DID string alone is insufficient. (The ephemeral MLS leaf key is not itself a DID verification method — it is the attestation over it, not the leaf signature, that resolves against the DID document.) The `{ id-agreement (step-4 a0) → block-list consent gate → confirm-bound-creator → fresh-join (consumes init key) → destroy }` steps execute **atomically under the per-context actor mutex + a generation/identity check**, with **the id-agreement check (step-4 a0) first and the block-list gate second**. On the convergence path, `did_hi`'s fresh-join is an **atomic in-place replacement** of its orphan in the `derived_context_id` slot — **a *replace-not-create*, not an additive second group**: under that same per-context actor mutex + generation/identity check, `join_from_welcome` validates the Welcome (consuming the single-use init key) and, **only on success**, installs `did_lo`'s joined group and destroys the orphan **as the same atomic operation**. The per-id `create_mls_group` `Entry::Vacant` guard (the *MLS-layer defense-in-depth* above) is therefore not implicated — the join **supersedes** the orphan rather than being created alongside it — and the replay-safety and single-node-vs-distinct-node window properties are exactly those stated under *Convergence window* below. On the convergence/collision path the **id-agreement check precedes and subsumes the consent gate**: a Welcome whose bound id does not match `did_hi`'s own re-derivation is rejected at (a0) and never reaches the block-list gate, so the two separately-worded "no join" outcomes — the (a0) mismatch/ignore decision and the consent-gate reject — are the single ordered path, not two competing gates. A node that holds a self-created group under the id and is itself `did_lo` (the lower DID) is the **survivor**: it ignores every inbound Welcome under that id — a purely local **survivor-role** determination (the matching id passes (a0); `did_lo` ignores because the Welcome's creator is `did_hi`, not the survivor `did_lo`), decided before consent evaluation and distinct from the (a0) id-agreement check. A node that is `did_hi` runs the full sequence (id-agreement (a0) → block-list → confirm-bound-creator → fresh-join → destroy). (This single sequence forecloses the forged-creator-string DoS, the replayed-Welcome stale-destroy, and the confused-deputy recreate-then-destroy, because the destroy is gated on the *same* single-use init-key consumption and §9.7.1 binding that gate the join, all under the mutex: a forged or non-`did_lo` creator fails confirm; a replayed/stale Welcome whose init key was already consumed fails the join and destroys nothing; a context recreated between confirm and destroy is caught by the generation check.) A group reached via the peer's Welcome is never self-created and is never destroyed by this rule.

`did_hi`'s rejoin-then-destroy **is itself a Welcome-join**, so `did_hi` inherits the same interim send-gating as any Welcome-joiner (*Send-capability caveat* below). The **block-list arm is the only consent-reject cause on this path** (the *Anti-spam* limiter below exempts any Welcome under an id for which this node already holds its own self-created group — the convergence path — and throttles only stranger/approval-prompt Welcomes; see that clause's gate-decidable carve-out). On a block-list hit `did_hi` performs no fresh-join and no destroy, keeping its own group and never joining `did_lo`'s — observably identical to any other consent-rejected Welcome. The stranger arm is satisfied implicitly: a `did_hi` to which this rule applies itself initiated a create for this exact pair (an explicit decision to form it), so `did_lo` is not a stranger here. A block already visible to `did_hi`'s node at the gate-read instant aborts the bundle; a not-yet-propagated block (§3.7.1 best-effort propagation) **self-heals** post-join — the only destination the bundle can converge to is the same `did_hi`-initiated pair under the identical id, and §3.7.1 post-join propagation severs `did_lo` — so `did_lo` can never force a *durable* join to a blocking peer (subject to the send-capability scope below).

**Convergence window.** Before `did_lo`'s Welcome reaches `did_hi` (e.g. `did_lo` crashed after its 1-leaf create but before emitting), both nodes MAY transiently hold **distinct self-created groups under the same id**. This is benign — `did_lo` builds no state from `did_hi`'s group, and MLS isolation prevents either reading the other's plaintext. Implementations MUST NOT assert single-group existence as a **synchronous** invariant during this window; the one-group guarantee is **eventual**, holding once `did_lo`'s Welcome is delivered (or re-driven via get-or-create). The "exactly one group survives (`did_lo`'s)" invariant is **eventual, restored by re-drive — not by the reaper window**. While `did_lo`'s own InvitationBundle is still deliverable, reaping is suppressed and convergence to `did_lo`'s group remains possible. **If the peer stays offline past `welcome_ttl`, `did_lo` MAY reap its canonical replica before convergence completes** (relay-retention expiry is independent of peer liveness); this is benign because the next `standing_context(peer)` get-or-create auto-revives and re-emits under the deterministic id, at which point the `did_hi` party joins `did_lo`'s group, then destroys its orphan, per *Concurrent-creation collision resolution*. The invariant is therefore the steady-state guarantee **after the most recent re-drive converges**, never a claim that a single emit window blankets an arbitrarily long pending interval. `did_lo` still never observes `did_hi`'s competing group — consistent with the "builds no state" rule.

**Async creation flow.** Ordinary single-context async MLS creation — no Prepare/Commit/Abort, no reserve-not-consume, no saga journal:

1. **Initiator (A) creates the group.** A recomputes `derived_context_id` and validates: (a) it is not already Active under the id (else the *Get-or-create idempotency* path applies — bare existence is not auto-failure); (b) `peer_did` is canonically **distinct from A's own DID** (using §3.8.1 canonical form on both sides; a self-pair is rejected with the same generic/typed malformed-peer rejection as any malformed peer DID, disclosing nothing). **Sybil non-credit (normative, §9.3 cross-ref):** beyond the self-pair guard, a standing pair between **two distinct DIDs the same operator controls** MUST NOT count toward §9.3 earned-capacity participation records — otherwise a Sybil operator could self-deal two of their own DIDs into participation credit. This is the same **not-self-created** discriminator §9.3 applies to participation records (a participation record only counts from a context the counting identity did not itself create/admin); a two-party context both of whose members the operator controls is self-dealt and does not earn capacity for either. (c) the `bilateral-persistent` template params are well-formed (§5.12.1); (d) `peer_did` resolves to a well-formed DID document with an Active Signing Key (§3) and is not blocked; (e) A's provider holds no group under the id (the `Entry::Vacant` guard; collision ⇒ error). On success A creates a **1-leaf** MLS group plus a fresh sender key.
2. **Add the peer.** A fetches B's published `KeyPackage` and `add_member`s B, producing a **Welcome**. B's KeyPackage single-use is enforced at B's *join* by the fused-join two-anchor mechanism (ADR-049 §9) — no Prepare-time reservation.
3. **Publish / register (A).** A publishes the group, emits the **InvitationBundle** (carrying the MLS Welcome as its `welcome_message`, §5.12.3.1) to B's personal routing id (the §5.12.3.3 invitations routing id) asynchronously (A does not block on B), so it rides the §5.12.3.3 invitation-delivery path and inherits the InvitationBundle 7-day relay-retention TTL (`welcome_ttl`, default — read by the reaper, item (d)); registers the context **Active**, appends the creation to its event log, and records the peer via `register_standing_context`.
4. **Peer (B) receives the Welcome and applies the consent gate on receipt** (*before* joining): (a0) **`derived_context_id` agreement (cross-party canonicalization check, defense-in-depth)** — B MUST **re-derive** the standing-pair `derived_context_id` from its **own** inputs (`local_did = B`, `peer_did = A`, each in §3.8.1 canonical form, sorted, length-prefixed per *Determinism precondition*) and verify it **equals** the context id the inbound InvitationBundle / Welcome binds. A mismatch — which can only arise from a DID-canonicalization divergence between A and B (e.g. an exotic did:web encoding the two sides normalize differently) — ⇒ **reject the Welcome (do NOT join)**, surfacing the same generic rejection as any other consent reject (no synchronous "Rejected" reply, per *Block-privacy* below). This is the **receive-side canonicalization backstop** §3.8.1's did:web residual relies on: it converts an **honest** DID-canonicalization divergence between A and B (the only way B's locally-derived id and the bundle's asserted `context_id` differ when A is honest) from a silent split-brain into a clean local rejection (routed through the generic consent-reject, leaking nothing). It is **not** a cryptographic cross-party agreement proof — `InvitationBundle.context_id` (§5.12.3.1) is a creator-asserted, creator-signed label, not a value bound to the DID pair, so a *malicious* A can always label the bundle with the id B will derive. Agreement against a dishonest creator on the collision path rests on the §9.7.1 bound-creator check and MLS membership binding (below), not on this equality test. **Non-mismatch resolution outcomes (a0).** If B cannot resolve or canonicalize `creator_did` (A's DID) at all — distinct from an id *mismatch* — the outcome is determined by the failure kind: a **transient** resolution failure (e.g. the DHT is momentarily unreachable) is a **retryable deferral**, NOT a permanent reject — B re-attempts within the `welcome_ttl` window rather than discarding the Welcome; a **permanent** un-canonicalizable-method case (a DID method that admits no canonical string form — the §3.8.1 fail-loud method-admission gate) is a **reject**. Neither path is ever a silent join: a still-pending transient deferral simply does not join yet, and a permanent failure rejects through the same generic consent-reject as a mismatch. (a) **block list** — refuse if A is globally blocked (§3.7.1 `is_globally_blocked`); (b) **default-deny for strangers (allowlist-or-prompt)** — a standing-pair Welcome from a **stranger** is **default-deny** (non-overridable, carrying the **same non-overridable intent** as §5.12.2's outlet-bearing rule: a conformant SDK MUST NOT let an `AutoAcceptPolicy` override the deny), justified by the pair's `memory_scope: full` sensitivity (§5.12.1). It MAY be auto-joined **ONLY** if A's DID is on the operator's `known_did` allowlist (§5.12.2 — the sole auto-accept trigger); otherwise B joins **only after explicit human approval**. This default-deny is a **MUST on conformant implementations at the SDK consent-gate layer**, not protocol-layer enforcement. If B's policy configures an `AutoAcceptPolicy` whose `known_did` allowlist contains A, B MAY auto-join; else B joins only after explicit approval. The gate is applied by the **joining peer on Welcome receipt**, never as a synchronous Prepare-B reply: on accept B joins (single-use enforced at join), registers Active, appends, and runs `register_standing_context`; on reject B simply **never joins** — no synchronous "Rejected" reply.

#### Threat model and operational contracts

**Block-privacy (consent-on-receipt).** Because consent is applied by the *joining* peer asynchronously, a blocked or unapproved initiator gets **no synchronous rejection**, foreclosing the **synchronous** block/pair-existence reply oracle a two-phase `Rejected` would leak. (That a decline is indistinguishable from offline/slow/blocking — the identical-`Ok` oracle closure — is stated once under *Ok-return contract* below.) **Scope (precise):** this closes the *reply* oracle only. A's step-2 fetch of B's **published** `KeyPackage` runs *before* the gate and is relay-observable, so a network observer can distinguish "B has a published KeyPackage" from a peer that never published one; the async gate does not claim to hide that. That published-KeyPackage bit becomes a *targeting* primitive only when chained with a stranger-bar bypass, which the **step-4(b) allowlist-or-prompt default-deny blunts (a candidate cannot self-clear an operator-set allowlist)**.

**Known limitation — wire-observable solicitation.** The "private contact graph" claim (§5.12.6) scopes to A's **local bookkeeping**. The standing-pair Welcome rides B's *publicly-computable* invitations routing id **unconditionally, before** the consent gate, so first-contact solicitation metadata + addressee DIDs are **observable to relays**. This is inherent to contacting a peer over an untrusted relay; consent-on-receipt closes only the synchronous *reply* arm, **not** solicitation visibility. The message *content* remains MLS-encrypted.

**Initiator-side never-joined steady state (normative).** Because A registers Active, appends, and runs `register_standing_context` in step 3 — independent of B joining — A may hold a **single-member replica indefinitely** if B never joins. This is the intended bounded steady state:

- **(a) Decline is indistinguishable from offline** — no synchronous `Rejected`, no peer-state probe; A observes only "B has not joined yet" (the identical-`Ok` closure across offline/slow/blocking/declining is stated once under *Ok-return contract* below).
- **(b) A-local bookkeeping only.** A's event-log entry and contact-graph edge carry **no cross-replica consistency obligation** until a second member exists; a single-member replica is internally consistent.
- **(c) B's join is observable only out-of-band** — an inbound Commit advancing the group to two leaves, or the first inbound message; never a synchronous confirmation.
- **(d) Reaper.** A MAY reap an orphaned single-member replica once the idle bound (the `bilateral-persistent` TTL / operator `close_context`, §5.12.6) elapses **AND** every InvitationBundle A emitted for B is past its relay-retention TTL. The undeliverability predicate is **A-local and observation-free**: A is the sole emitter and computes it as `now > max(per-relay emit timestamps) + welcome_ttl` over every relay it emitted to — **no relay or B query** (a re-drive resets the window). Reaping is **safe-by-construction**: a reaped or never-joined handle does not dangle — the next `standing_context(peer)` auto-revives the pair under the deterministic id (ADR-049 §10 (standing-context auto-revive residual)). **Collision guard.** `did_lo`'s reaper deliverability window is keyed **solely on its own emit timestamps** (`now > max(per-relay emit ts) + welcome_ttl`). Because `did_lo` re-drives its own `add_member` + InvitationBundle-emit on every `standing_context(peer)` get-or-create (resetting the window), and because `did_hi`'s canonical convergence is triggered by `did_lo`'s InvitationBundle (not the reverse), `did_lo` need not observe `did_hi`'s competing group to remain reap-safe: while `did_lo`'s own InvitationBundle is still deliverable (window not elapsed) convergence is still pending, so reaping is already suppressed. `did_lo` **MUST NOT** key reap-suppression on observing a competing peer Welcome — consistent with the "builds no state from `did_hi`'s group" rule above.

**Anti-spam rate limit (normative).** B MUST rate-limit *inbound* standing-pair Welcomes **per initiator DID** on the consent gate — an ordinary per-peer cooldown, default **60 s**, hard floor **1 s** (a near-zero cooldown is non-conformant); operators surfacing approval prompts as interrupts SHOULD prefer the default. **Scope carve-out (gate-decidable).** The cooldown is evaluated at the consent gate using **only locally-available state**: a Welcome under a `derived_context_id` for which this node **already holds its own self-created group** is a convergence candidate and is **exempt** from the per-initiator cooldown (its authenticity is settled downstream by confirm-bound-creator + init-key single-use, which a forged variant fails before consuming an init key or destroying anything). **Disclosed cost of the exemption (honest):** a forged convergence-candidate Welcome under such an id is not free — confirm-bound-creator still performs one **DID resolution + signature verification** before rejecting it, and that work is **not** rate-limited by this cooldown. This is bounded because the exemption's precondition is that the victim **already holds a self-created group under that exact id**, which requires the victim to have itself initiated the pair — so an attacker cannot manufacture the precondition on an arbitrary victim (no self-created group under the id ⇒ the Welcome is a stranger/approval Welcome and IS cooldowned). **The precondition is not exotic, however (honest amplifier disclosure):** it is satisfied for **every real standing pair the victim has ever initiated**, and the `derived_context_id` is **publicly computable** from the two participant DIDs — so **any** party (not only the actual peer) who knows both DIDs can forge convergence-candidate Welcomes under such a known id, forcing the **un-throttled** confirm-bound-creator DID-resolution + signature-verification work for each. It remains a **bounded** DoS — exactly one DID-resolve + one signature-verify per Welcome, with **no amplification beyond that** (no join, no state change, no fan-out) — but the cost is real and is stated honestly rather than implying the precondition is hard to reach. **DID resolution is a NETWORK operation, not merely local CPU:** resolving `creator_did` is a DHT lookup (did:dht) or an HTTPS fetch (did:web), so an off-path party who knows both DIDs (the id is publicly computable) can force the victim into **outbound resolution traffic against a third party's DID host** — a bounded **reflected-resolution** vector, one resolution per forged Welcome (still no join / state-change / fan-out). All other inbound standing-pair Welcomes (no pre-existing self-created group under the id) are stranger/approval-prompt Welcomes and **ARE** subject to the per-initiator cooldown. Convergence is thus never gated on the inbound cooldown, and the carve-out needs no post-gate creator-binding to decide. This is not saga concurrency machinery. **Residual (honest, per §9.3):** the per-DID cooldown does not bound a **fresh-DID fleet** (many DIDs, one Welcome each). That fleet is an **approval-prompt-spam DoS, not an unauthorized-join flood**: the step-4(b) default-deny means each of N fresh strangers still requires explicit out-of-band approval, so the fleet yields at most N approval prompts, never N silent joins — bounded by the §9.3 per-identity minting cost each DID pays to become admissible. §9.3 defines no recipient-side inbound tier check, so this spec claims none and authors **no** new standalone limiter. There is **no** standing-pair-specific KeyPackage reservation: single-use is enforced at join (step 2); a stranger-add draining A's KeyPackage pool is the **general MLS KeyPackage-pool concern**, bounded by republication and §9.3.

**Replica synchronization & authenticity.** Both members hold a replica of the one context, synchronized by **MLS** (epoch-ordered Commits + the bootstrapping Welcome) and the event-log RFC-6962 layer (§17) — no saga journal. Authenticity derives from MLS: B's Welcome processing cryptographically binds B into A's group, and this **MLS Welcome membership binding is the load-bearing A→B authenticity anchor in the interim** — sufficient on its own. The per-message Ed25519 InnerEnvelope signature is an additional anchor available once bidirectional send lands (Phase 2E); until then a Welcome-joined node cannot SEND, so no joiner-originated signed message exists yet. There is **no** signed creation receipt, **no** commitment journal, and **no** `secret_bearing` saga apparatus — MLS secrets live only in actor-local crypto-provider state.

**Send-capability caveat — ALL Welcome-joiners (normative; single source of truth for send-gating).** Per ADR-049 §Follow-ups #1, **any party that obtains its replica via Welcome-join** — the non-initiating common-case peer AND the collision-losing `did_hi` — can join and **DECRYPT** but **cannot SEND** until the Phase-2E spawn-from-Welcome entrypoint lands. This is the most frequent path, not an edge case: a Welcome-joined `Ok` reflects *replica-created and decryptable* but **interim send-gated** until Phase-2E; A's (initiator) sends are unaffected. **This gating is security-relevant, not merely a feature gap:** a simultaneous-create collision is attacker-influenceable — a peer who is `did_lo` relative to a victim can deterministically race a create to push the victim (`did_hi`) onto this send-gated path. Bounded — the attacker must already be a consent-passed pair member, and the worst case is the victim being receive-but-not-send **in that one pair** until Phase-2E, never a cross-pair effect or key exposure. All other clauses that mention send-gating refer back here.

**Self-heal severance scope (current durable reality, not just a Phase-2E follow-up).** §3.7.1 severance requires a sender-key rotation (a SEND, §3.7.1 / §9.16.3), so the unobserved-block self-heal above is performed by the **send-capable side** (the initiator) on next connection; a **send-gated Welcome-joined replica** (the common joiner, and a collision-losing `did_hi`, per *Send-capability caveat* above) **cannot sever until Phase-2E**. The "`did_lo` can never force a durable join to a blocking peer" end-state convergence therefore holds **conditioned on the blocking side being send-capable**. **This is a current durable reality, not just a follow-up — and it is an ACTIVE channel, not a passive one:** where the attacker is `did_lo` and the blocking victim is the send-gated `did_hi`, there is **presently** a durable, attacker-refreshable, decrypt-capable `did_lo`→`did_hi` content-delivery channel that a blocked `did_lo` can **keep delivering content into** a send-gated `did_hi` blocker until Phase-2E ships. The blocker has **no key-level escape primitive** in the interim: `close_context` does not escape it either, because the deterministic id means a `close_context` followed by any later `standing_context(peer)` **re-derives the same context** under the same id. **Interim mitigation within a send-gated node's power (normative SHOULD, receive-side only):** a blocked-and-send-gated `did_hi` SHOULD apply a **receive-side drop-filter** — suppressing **application-surfacing** of inbound content from a `did_lo` it has blocked. **Precise scope (no over-claim of deprivation):** the filter suppresses application-surfacing *only*; it does **not** sever. `did_hi` remains a **live MLS member** and MUST still process `did_lo`'s inbound traffic to keep its MLS ratchet in epoch sync, so a **resource + ratchet-advancement + presence residual persists** until Phase-2E — the attacker still costs `did_hi` decryption/ratchet work and still observes `did_hi`'s liveness; the filter denies the *application surface*, not the channel. **The severance end-state is conditioned on conformant receive-side behavior:** the drop-filter is a normative SHOULD with **no cryptographic or mechanical enforcement**, so a non-conformant or lagging SDK build simply does not apply it — there is no protocol-level guarantee it runs. Severance proper (sender-key rotation, which is a SEND — §3.7.1 / §9.16.3) cannot occur until the Phase-2E spawn-from-Welcome entrypoint makes `did_hi` send-capable (ADR-049 §Follow-ups). The honest bound is unchanged: **in that one pair only**, no cross-pair effect, no key exposure — `did_hi` reads nothing of `did_lo`'s that MLS does not already deliver.

**`standing_context` Ok-return contract (normative).** A successful return means the **initiator's replica is created and the Welcome dispatched** — it does **NOT** imply the peer joined or that a bidirectional channel exists. An offline, slow, blocking, and declining peer **all yield the same `Ok`** (join observed only out-of-band; intentionally no synchronous confirmation — block-privacy above) — this is the single statement of that identical-`Ok` oracle closure. A `Welcome`-join `Ok` is additionally **interim send-gated** per *Send-capability caveat* above. A reaped or never-joined handle does **not** dangle — the next call auto-revives under the deterministic id (ADR-049 §10 (standing-context auto-revive residual)). Get-or-create returns the **identical handle type** whether it created or found the pair: **no typed create-vs-found or `peer_joined` discriminant in the return value** (a verified member MAY observe found-vs-create *latency* for their own pair, §5.12.5, but a typed discriminant and any non-member observation are foreclosed). **FFI/SDK bindings MUST NOT enrich the return with a create-vs-found or `peer_joined` discriminant** (e.g. a `created: bool`) — the uniform `Ok` is what forecloses the synchronous block/pair-existence oracle; the shape MUST be identical across all bindings (every SDK language). The sole non-`Ok` outcomes are genuine failures (malformed/self peer DID, a peer A itself blocked, or the existence-oracle generic rejection) — never a typed signal about the peer's join decision.

**Get-or-create idempotency.** `register_standing_context` records a peer DID in the contact graph (§5.12.6) — local bookkeeping that lets `standing_context(peer_did)` resolve get-or-create without re-creating the group (idempotent — a redundant re-run is a no-op). It is an **internal contact-graph operation, never an FFI export** (mirroring ADR-049 §3a); the FFI/SDK surface is `standing_context(peer_did)` get-or-create alone. A get-or-create surfacing `AlreadyExists` under the deterministic id maps to idempotent **success based strictly on verified-self-membership** — id-determinism guarantees the existing context IS this exact pair, so a verified member re-runs the idempotent registration and returns it; non-members get the generic rejection (existence-oracle clause below). A crash between create/join and the registration write is closed by the next get-or-create. **Self-only group is not success-without-re-drive:** a bare group where the **peer is not yet a member and no Welcome was durably emitted** (crash after the 1-leaf create but before `add_member` / Welcome-emit) is half-created — get-or-create MUST re-drive the **idempotent** `add_member` + Welcome-emit (+ publish / register) to completion for whichever party created it. (A node that instead received the canonical peer's Welcome resolves it per *Concurrent-creation collision resolution* rather than re-driving its own group.) Verified-self-membership maps to immediate success **only** once the peer is a member OR a Welcome was durably emitted. **Residual (disclosed):** a `did_hi` self-only re-drive references one of `did_lo`'s published single-use KeyPackages to build its Add, producing a Welcome `did_lo` will **ignore** (per *Concurrent-creation collision resolution*). Because `did_lo` never processes that Welcome, **`did_lo`'s KeyPackage is never consumed** (single-use is enforced at the invitee's join, step 2) and remains available for the canonical pairing — **no pool drain occurs**. `did_hi`, on receiving `did_lo`'s canonical Welcome, joins `did_lo`'s group and then destroys its orphan. The init-key single-use plus `did_lo`'s ignore-rule preserve single-group convergence.

**`AlreadyExists` is not an existence oracle.** An `AlreadyExists` for an id the caller is **not a verified member of** MUST NOT return `Ok` (it would leak that a pair between two DIDs exists — the contact graph is private local bookkeeping, §5.12.6). The non-member path MUST return a response **indistinguishable in value AND timing** from the generic rejection any other failure returns — it MUST be constant-time with respect to existence, because an existence-dependent latency branch is itself a 1-bit oracle even when the returned value is identical. The typed `AlreadyExists`→`Ok` outcome is reserved **strictly** for verified-self-membership. **Implementer mechanism:** resolve membership **first**, then branch only on *membership* — a non-member and a no-such-context input traverse the same fixed-cost lookup work (`derived_context_id` resolution + membership check) and return the same generic rejection; existence MUST NOT be a branch the latency depends on. The §5.12.5 found-vs-create latency hint (`~0ms` found vs `~200ms` create) applies **only to a verified member's own pair** on the success path, never to the constant-time non-member path. **Reachability (defense-in-depth scope).** The non-member path is reachable **only** via a **raw-`derived_context_id`** join/resolve attempt, never via `standing_context(peer)` itself: `standing_context(peer)` derives the id from the **caller's own DID** + `peer` (sorted, length-prefixed, *Determinism precondition*), so the caller is a pair member **by construction** and cannot address a pair it is not in. The constant-time non-member defense thus guards a raw-`derived_context_id` entry point rather than the `standing_context(peer)` surface — and because `derived_context_id` is publicly computable from any two DIDs (see *Anti-spam* above), that raw entry point is a **concretely reachable** existence-probe surface: the value-AND-timing constant-time requirement on it is **load-bearing for any binding that accepts a raw context id**, not optional hardening.

Cross-refs: §5.12.6 (standing contexts / contact graph; private local bookkeeping), §5.12.1 (`bilateral-persistent` template), §5.12.2 (`AutoAcceptPolicy` / `TrustRequirement` — allowlist-only), §5.12.3.3 (InvitationBundle relay-retention TTL), §5.12.5 (found-vs-create latency hint), §3.8.1 (canonical DID string form for deterministic derivation), §3.7.1 (block list / severance — sender-key rotation), §9.3 (Sybil resistance / earned capacity), §9.5.1 (length-prefix framing), §9.6.1 (did:dht self-certification / z-base-32 canonical form), §9.7.1 (MLS-to-SCP Concept Mapping — KeyPackage-attestation / DID-VM binding rule), §9.16.3 (sender key rotation), §17 (event-log consistency / checkpoints), §6.2.4 (cross-context outlet invocation saga), ADR-049 §3 / §3a / §9 / §10 / §Follow-ups (single-context async creation, not a saga; fused-join single-use; auto-revive; spawn-from-Welcome).
