# 8. Products and Apps in the Graph

## 8.1 Apps in the Protocol

An app is not a protocol entity. It has no DID, is not an agent, and is not a context. The protocol has no `App` type.

What people experience as "an app" is a composite: a context (or set of contexts) + its members + its data + the backend, hosting, and relays that support it. The client is just the visible surface. The app's identity is the whole gestalt — the community, the infrastructure, the accumulated state. This is a philosophical identity, not a codified one. The protocol doesn't need to model it because the constituent parts (contexts, members, tools, data, capability declarations) are already first-class. The app emerges from their composition.

What the protocol *does* ensure is that this emergent identity never becomes lock-in: protocol state is portable (§8.3), clients are switchable, and no app owns the social graph.

## 8.2 App Interface

Apps declare what capabilities they need from the protocol. The protocol provides them. The interface is self-documenting and machine-readable, optimized for agent consumption rather than human developers hand-coding against it.

Apps can be any shape: thick clients with minimal protocol reliance, thin shells that are mostly protocol, or anything in between. The protocol doesn't care. It provides identity, social graph, contexts, tools, trust, and transport. The app decides what to use.

## 8.3 Context Portability and State Layering

State in SCP exists at two layers:

**Protocol state** — membership, roles, capability tokens, tool registrations, governance model, content history, trust relationships. This belongs to the protocol and the context, not to any app. It is portable, app-independent, and survives app death. Any app that declares the right capabilities can attach to an existing context and access its protocol state.

**App state** — data structures, configurations, and artifacts specific to a particular app's functionality. A game's world state. A project tracker's task board. A collaborative document's edit history. This belongs to the app. It may live in the context (stored via protocol data primitives) or entirely outside it (in the app's own infrastructure). The protocol doesn't claim ownership of app state, and apps are free to manage it however they choose.

The boundary between the two is the protocol's anti-lock-in mechanism. If you leave an app, you lose its app state (unless the app chooses to make it portable). You never lose your membership, your roles, your trust relationships, your identity, or your social graph. The social infrastructure is not hostage to any app's business decisions.

This means:

- **App switching.** A group can switch apps without losing their context's social infrastructure. Membership, roles, trust relationships persist. App-specific state may or may not transfer — that depends on the apps, not on the protocol.
- **Simultaneous multi-app.** Different members of the same context can use different apps. Alice uses a community app. Bob uses a custom-generated client. Carol uses a minimal terminal app. They share protocol state. Each has their own app-layer experience.
- **App death is survivable.** If an app stops working, the context's social infrastructure survives. App-specific data may be lost if the app didn't store it durably, but the people, the relationships, and the trust graph remain. Generate a new app and the context continues.
- **Thick apps are welcome.** An app with rich proprietary state (a game, a design tool, a financial instrument) is a first-class participant. The protocol doesn't demand that all state be portable — only that the social layer is. Apps compete on their app-layer value, not on social graph lock-in.

## 8.4 Capability Declaration Contract

Apps interact with the protocol through a **capability declaration** — a structured, machine-readable manifest of what protocol capabilities the app needs. The protocol validates the declaration against the context's capability ceiling and the user's granted permissions, then provides exactly what was requested.

```
App → Protocol:  "I need: messaging, member_list, outlet_call(outlet_a, outlet_b)"
Protocol → App:  "Granted. Here are your interfaces."

App → Protocol:  "I need: messaging, member_list, invite_members"
Protocol → App:  "Denied: invite_members exceeds your agent's role in this context."
```

The declaration contract is the boundary that makes generated apps safe. An LLM generating a client doesn't need to understand SCP internals — it declares what it needs, and the protocol handles authorization, scoping, and enforcement. The attack surface of a badly-generated app is bounded by the declaration contract, not by the app's code quality.

Properties:

- **Declarative, not imperative.** Apps say what they need, not how to get it.
- **Validated against ceiling + role.** The protocol never grants more than the context allows and the agent's role permits.
- **Machine-readable and self-documenting.** An agent can read a capability declaration and understand what an app does without running it. This enables trust evaluation of apps themselves.
- **Versionable.** Declarations carry a protocol version. Apps built against older declarations continue to work. Forward compatibility is a protocol constraint.

### 8.4.1 Capability Declaration Wire Format

The capability declaration uses JSON Schema (MCP-compatible) with SCP-specific extensions. The declaration is a JSON object with the following structure:

```json
{
  "scp_version": "1.0",
  "app_id": "did:dht:app_publisher_did",
  "app_name": "My App",
  "app_version": "2.1.0",
  "capabilities": [
    {
      "resource": "scp:ctx:{context_id}/messaging",
      "actions": ["read", "write"],
      "constraints": {
        "max_message_size": 65536,
        "media_types": ["text/plain", "application/json"]
      }
    },
    {
      "resource": "scp:ctx:{context_id}/members",
      "actions": ["read"]
    },
    {
      "resource": "scp:ctx:{context_id}/tools/{tool_id}",
      "actions": ["invoke"],
      "constraints": {
        "max_invocations_per_minute": 60
      }
    }
  ],
  "min_role": "member",
  "signature": "<Ed25519 signature by app_id over canonical JSON of this object excluding the signature field>"
}
```

**Field definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scp_version` | string | Yes | SCP protocol version this declaration targets. Format: `"MAJOR.MINOR"`. SDKs MUST support declarations with the same MAJOR version and any MINOR version <= current. |
| `app_id` | DID | Yes | DID of the app publisher. Used for trust evaluation and revocation. |
| `app_name` | string | Yes | Human-readable app name. Maximum 128 UTF-8 bytes. |
| `app_version` | string | Yes | App version. SemVer format (`MAJOR.MINOR.PATCH`). |
| `capabilities` | array | Yes | List of requested capabilities. Each entry specifies a resource URI and actions. Minimum 1 entry, maximum 64 entries. |
| `capabilities[].resource` | string | Yes | SCP resource URI. Format: `scp:ctx:{context_id}/{capability_category}` or `scp:ctx:{context_id}/tools/{tool_id}` for specific tools. The `{context_id}` is a template variable resolved at binding time. |
| `capabilities[].actions` | array | Yes | Actions requested on the resource: `"read"`, `"write"`, `"invoke"`, `"admin"`. Minimum 1 action. |
| `capabilities[].constraints` | object | No | Optional constraints on the capability (rate limits, size limits, type restrictions). App-defined; the protocol validates that constraints are a subset of the context's ceiling. |
| `min_role` | string | Yes | Minimum context role required for this app to function. Built-in roles: `"observer"`, `"member"`, `"moderator"`, `"admin"` (§5.5). Contexts may also define custom roles; apps targeting custom roles should use the custom role name here. |
| `signature` | string | Yes | Ed25519 signature by `app_id` over the canonical JSON serialization (RFC 8785 JCS) of the declaration with the `signature` field removed. |

**Validation:** The SDK validates the declaration at binding time (when an app attaches to a context):

1. Verify `scp_version` is compatible with the SDK's protocol version.
2. Verify `signature` against `app_id`.
3. For each requested capability, check that the capability category exists in the context's ceiling (§5.3) AND the agent's role includes the requested actions.
4. If all capabilities are grantable, the declaration is accepted. If any capability is denied, the entire declaration is rejected (all-or-nothing). The rejection response includes a `denied_capabilities` array listing which capabilities failed and why.
5. The validated declaration is stored in the context's tool registry for auditability.

### 8.4.2 SDK-Level Enforcement

The SDK is the enforcement boundary for capability declarations. Apps interact with the protocol exclusively through SDK-provided handles that are scoped to their declared capabilities. The SDK MUST NOT provide unscoped or privileged access to any app — all protocol access flows through capability-checked entry points.

**Enforcement mechanics:**

1. **Registration.** Apps register their capability declaration (§8.4.1) with the SDK before binding to any context. The SDK validates the declaration's signature, protocol version compatibility, and structural correctness. Invalid declarations are rejected at registration time — the app never receives a handle.

2. **Bind-time validation.** When an app binds to a context, the SDK checks every declared capability against the context's ceiling (§5.3) and the agent's current role (§5.5). If any capability is not grantable, the entire binding is rejected (all-or-nothing semantics). On success, the SDK returns a **scoped handle** — a context handle that only exposes the APIs corresponding to granted capabilities.

3. **Runtime enforcement.** The SDK MUST reject API calls that exceed the app's declared capabilities at the call site. An app that declared `["read"]` on `messaging` MUST receive an error if it attempts to call `send_message()`. This is a hard enforcement boundary, not a suggestion. The rejection is immediate (no governance vote, no capability negotiation) and returns a `CapabilityDenied` error with the missing capability.

4. **No capability escalation.** Once bound, an app cannot request additional capabilities without re-registration with a new declaration. The SDK does not support runtime capability grants. If an app needs expanded capabilities, it must present a new (or updated) signed declaration from its publisher.

5. **Scoped handle isolation.** Each app receives its own scoped handle to the context. Scoped handles are not interchangeable — an app cannot use another app's handle to access capabilities it did not declare. The SDK maintains per-app-binding state that maps the handle to the validated declaration.

**Auditability.** The validated declaration is recorded in the context's event log at bind time. Context members can inspect which apps are bound and what capabilities they hold. App binding and unbinding events are visible in the event log — silent app attachment is not possible.

## 8.5 MCP Compatibility (Model Context Protocol)

MCP (Model Context Protocol) defines how AI models connect to tools and data sources locally — a JSON-RPC protocol where servers expose tool schemas, models discover and call them. MCP and SCP operate at different layers and integrate naturally.

```
┌──────────────────────────────────────────────────────┐
│  AI Model (any model that speaks MCP)                 │
│                                                        │
│  Sees tools. Calls tools. Gets results.               │
│  Has no awareness of SCP.                             │
└────────────────────┬─────────────────────────────────┘
                     │ MCP (JSON-RPC, local)
                     │
┌────────────────────▼─────────────────────────────────┐
│  SCP Agent (local process)                            │
│                                                        │
│  MCP server (local side) ←→ SCP participant (network) │
│                                                        │
│  - Exposes context tools as MCP tool schemas          │
│  - Filters tools by role + capability tokens          │
│  - Signs with #active or #agent from human's DID      │
│  - Encrypts/decrypts context envelopes                │
│  - Surfaces context events as MCP resources           │
└────────────────────┬─────────────────────────────────┘
                     │ SCP Protocol (encrypted, over transport)
                     │
┌────────────────────▼─────────────────────────────────┐
│  SCP Context [tools, roles, members, governance]      │
└──────────────────────────────────────────────────────┘
```

The SCP agent is a translation layer: an MCP server from the model's perspective, an SCP protocol participant from the network's perspective. This separation has several consequences:

**Any MCP-compatible model participates in SCP without modification.** The model doesn't need to know about DIDs, capability tokens, encryption, or context governance. It sees tools. "Send a message" is a tool call. "Read recent messages" is a tool call. "Invoke the scheduling tool" is a tool call. The agent handles everything SCP-specific.

**SCP tool schemas should use MCP's format.** If SCP defines its tool interface using MCP-compatible JSON schemas, then SCP context tools are natively MCP-compatible with zero translation. The agent passes tool schemas through directly. This is a concrete design decision: SCP tool definitions should be a superset of MCP tool definitions, adding SCP-specific metadata (context scope, capability requirements, provenance) while keeping the core schema MCP-compatible.

**Capability filtering happens at the agent.** MCP has no concept of access control — configured tools are available. SCP tools are capability-gated by role. The agent resolves this by exposing only the tools the human's role permits. Tools the agent lacks capability for are never surfaced to the model — from the model's perspective, they don't exist.

```
Context tools:             Admin's agent MCP surface:    Member's agent MCP surface:

  tool_a (admin+)            tool_a ✓                      (not exposed)
  tool_b (member+)           tool_b ✓                      tool_b ✓
  tool_c (member+)           tool_c ✓                      tool_c ✓
  tool_d (observer+)         tool_d ✓                      tool_d ✓
```

**Multi-context as namespaced MCP tools.** A human in multiple contexts has their agent expose tools from all contexts, namespaced by context. The model sees `context_a/send_message`, `context_b/schedule_meeting`. The agent routes each call to the right context, with the right tokens, over the right encrypted channel.

**MCP provides the local wiring. SCP provides the social infrastructure.** MCP solves "how does an AI model connect to tools on this machine." SCP solves "how do those tools exist in a multi-party, trust-evaluated, persistent, access-controlled social space." MCP has no identity, trust, multi-party coordination, or persistence. SCP provides all of these. Together, they give any MCP-speaking model access to SCP's social infrastructure without either protocol needing to change.

**BYOA benefit.** "Bring your own agent" (§4.4) means users choose their own AI model. MCP compatibility means any MCP-speaking model works — Claude, GPT, Gemini, open-source local models, or anything future. The SCP agent handles protocol mechanics. The model handles reasoning. The user chooses both independently.

### 8.5.1 MCP ↔ SCP Boundary Translation

SCP uses **outlet** (§5.4) where MCP uses **tool**. The two words describe the same wire shape — stateless input→output functions gated by schema and capability — but SCP's context-centric vocabulary conflicts with MCP's agent-centric vocabulary when they meet at the boundary. The `scp-mcp` crate (`crates/scp-mcp/`) is a purely lexical translator: it rewrites identifiers and JSON Schema field names in one direction on each hop, preserving structure, semantics, and wire order. No state is kept across translations. No semantics are changed. Translation is mechanical and bidirectional by construction.

```
MCP side                                SCP side
───────────────────────────────────     ─────────────────────────────────
tools/list            →  outlet list        (ctx.outlets.list)
tools/call            →  outlet invoke      (ctx.outlets.invoke)
tool.name             →  outlet_id
tool.description      →  description
tool.inputSchema      →  schema.input
tool.outputSchema     →  schema.output
tools/list_changed    →  OutletUpdated / OutletRegistered / OutletDeregistered
CallToolRequest       →  OutletStreamOpen (non-streaming: single-chunk collapse)
CallToolResult        →  collected stream  (Data + End chunks flattened)
isError               →  OutletError envelope (§5.4.4)
```

**Kind projection (§5.4.2).** MCP has no concept of Query/Action. When SCP outlets are exposed over MCP, the translator prefixes `outlet_id` with `query.` or `call.` in the MCP-facing view so MCP-consuming models can tell them apart lexically (e.g., the SCP outlet `current_weather` with `kind: Query` surfaces as MCP tool `query.current_weather`). The `.` delimiter is chosen deliberately over `/` because MCP JSON-RPC reserves `/` as the method-separator convention (e.g., `tools/list`, `tools/call`); a `/` inside `tool.name` would conflict with MCP-routing parsers that split on `/`. The `.` character is unambiguous in MCP tool names and matches the dot-separated slug convention used elsewhere in SCP (e.g., error slugs `authorization.denied`). When MCP tools are exposed into SCP, the translator defaults `kind: Action` unless the upstream MCP server advertises the SCP-specific `x-scp-kind` JSON Schema extension.

**Streaming projection (§5.4.5).** MCP today uses synchronous call/result. The translator collects chunks on the SCP side before responding to MCP. Streaming-aware MCP extensions (if standardized) can be mapped to SCP's `OutletStreamChunk` at a later revision; the wire types (`OutletStreamOpen/Chunk/Credit`) are already defined to accommodate direct mapping.

**Error projection (§5.4.4).** SCP `OutletError` envelopes are surfaced to MCP clients as `CallToolResult { isError: true, content: [...] }` with the SCP error code encoded in a `meta.scp_error_code` field so that MCP clients aware of SCP can recover structured data. The `source_chain` is preserved as `meta.scp_source_chain` — lossy for MCP-only clients, round-trippable for SCP-aware ones.

**Why a lexical translator and not protocol unification.** MCP is an ecosystem with upstream that SCP does not control. Forcing MCP clients to adopt SCP's vocabulary would mean no MCP-speaking agent could talk to SCP without SCP-specific code. Forcing SCP to use MCP's vocabulary would pin SCP's semantics to an external spec's naming decisions. The lexical translator at the boundary lets both vocabularies stay stable and lets the SCP core use the context-centric word that matches its security model.
