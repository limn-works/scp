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

## 5.3 Capability Ceiling

Every context declares a capability ceiling at creation: the maximum set of things that can happen in this space. This ceiling bounds what tools can do, what roles can grant, and what agents can exercise. Standard capability categories include:

- **`messaging`** — text and structured data exchange
- **`toolInvocation`** — executing context-registered tools
- **`media.voice`** — real-time voice communication (§10.9.1)
- **`media.video`** — real-time video communication (§10.9.1)
- **`media.screenShare`** — screen sharing (§10.9.1)
- **`bridging`** — bridge connector participation (§12)
- **`toolInterface`** — cross-context tool interface exposure (§6.2)
- **`childContext`** — creating child contexts (§5.13)

Media capabilities (`media.*`) enable the delegated media transport model (§10.9.1) where the context establishes identity, trust, and governance while media flows over WebRTC/DTLS-SRTP. A context without media capabilities in its ceiling cannot initiate voice or video sessions regardless of participant roles.

Capability categories apply uniformly across context modes. `messagesRead` and `messagesWrite` retain the same abstract meaning in both Encrypted and Broadcast modes — the `ContextMode` determines the encryption pipeline, not the capability semantics. A `messagesWrite` UCAN in an Encrypted context authorizes MLS-encrypted message sending; the same capability in a Broadcast context authorizes broadcast-key-encrypted publishing.

Every context also declares a **ceiling policy** at creation — whether the ceiling can change and how. The ceiling policy itself is immutable (locked at creation, cannot be changed). Two policies are available:

- **`immutable`** (default for all well-known templates): Ceiling cannot change after creation. To expand capabilities, create a new context and migrate. Strongest security guarantee — members know the ceiling they opted into is permanent.
- **`governed`**: Ceiling can be modified through the context's governance model (admin, multi-sig, consensus). Changes are logged in the event log and visible to all members before taking effect. Members who joined under a narrower ceiling are notified and may leave before the expansion takes effect.

The ceiling policy is visible in context metadata (§5.7) before opt-in. A prospective member sees both the current ceiling and the policy governing changes.

**Economic policy is orthogonal to capability ceiling.** Ceiling governs what CAN happen; economic policy (§19.3) governs what it COSTS. Economic policy is not a ceiling category — it does not restrict or expand what actions are available, only what they cost.

## 5.4 Tools

Contexts provide tools: stateless functions that agents invoke. Tools have no identity, no agency, no ability to initiate. They take input and return output. They are scoped to their context and cannot span contexts.

Tools are the protocol's answer to "what about bots?" — anything that would have been a bot in a traditional system is a tool in SCP. The critical difference: tools cannot act, only respond. All agency flows through accountable agents.

Tool registrations include:

- **Schema.** Input and output types (MCP-compatible JSON Schema — see §8.5). Machine-readable, self-documenting.
- **Implementation hash.** Content-addressable reference to the tool's implementation. Any change to the implementation produces a new hash.
- **Test vectors.** Known input-output pairs that define correct behavior. Any agent can call the tool with test inputs and verify outputs match. This enables continuous integrity verification (§7.3.3).
- **Operator DID.** The identity accountable for the tool. Tool misbehavior traces to this DID.
- **Cost metadata (optional).** Per-invocation cost declared by the tool, additive with context-level costs (§19.3). Fields: `cost: Option<Amount>`, `cost_currency: Option<CurrencyCode>`, `cost_payee: Option<DID>`. A tool calling an external API can pass through its cost. Tool costs carry their own payee DID, which may differ from the context payee. Tools without cost metadata are free.

Tool mutations (implementation hash change, schema modification, test vector update) are recorded in the context's verifiable event log (§7.3.1). Silent tool modification is not possible — any change is visible to all context members.

## 5.5 Roles

Contexts define roles with specific permission sets within the capability ceiling. Roles determine which tools an agent can invoke, what data it can access, whether it can invite others, modify settings, etc.

Properties of roles:

- **Visible before opt-in.** You see what role you'd get before joining.
- **Non-negotiable.** Agents cannot request or bargain for different roles. Take it or leave it. If you want a different role, ask the context creator (human to human) or create your own context.
- **Defined by context creator.** Custom roles beyond defaults are context-specific.
- **Governed by context governance model.** Role changes require whatever governance the context uses.

**Broadcast context roles.** Broadcast contexts (§5.14) extend the role system with two mode-specific roles that reuse existing primitives:

- **Author** — holds `messagesWrite` UCAN. Can publish broadcast-key-encrypted content. Authors are bounded (added via `roleAssigned` events with role `author`). Each author maintains their own broadcast key with an independent epoch counter.
- **Subscriber** — holds `messagesRead` (auto-granted on DID-authenticated registration in open broadcast contexts, or requiring an explicit admin-issued UCAN in gated broadcast contexts). Subscribers receive author broadcast keys on request. Subscribers are unbounded.

The author/subscriber distinction mirrors the writer/reader two-tier model from discovery contexts (§6.2.2B). Open broadcast subscriber registration follows the same DID-authenticated pattern as discovery context reader-tier access.

## 5.6 Membership

One agent per human per context. Membership is transparent — participants can see the member list, roles, and agent capability metadata. When you opt into a context, you know what you're walking into.

**Broadcast context membership.** Broadcast contexts use a two-tier membership model: authors (MLS-equivalent bounded writers) and subscribers (unbounded readers registered via DID-signed requests). Subscriber registration records membership via `MemberJoined` events with role `subscriber`. The member list includes both tiers. Subscriber count is visible in metadata.

## 5.7 Metadata

The following are visible before opting in to any context:

- Template ID, if created from a well-known template (§5.12)
- Capability ceiling and ceiling policy (`immutable` or `governed`, §5.3)
- Available roles and their permission sets
- Governance model
- Creator identity
- Member count
- Context age
- TTL / time-to-live, if set (§5.10)
- Promotion policy (`no_promotion` or `promotable`), if context has a TTL (§5.10)
- Memory scope (§5.11)
- Context mode (`Encrypted` or `Broadcast`, §5.14)
- Economic policy, if set (§19.3) — pricing, accepted adapters, payee
- Active tool interface count (inbound and outbound, §6.2, §9.2.1)
- For child contexts (§5.13): parent context IDs, parent metadata summaries, parent governance configuration, and the prospective member's eligibility basis (§5.13.6)

This is protocol-level metadata, not optional. Full legibility of any space before you enter it. When a template ID is present, the joining party can evaluate the context with a single template-level check rather than inspecting each parameter individually — the template is a commitment that the parameters match the well-known definition exactly (§5.12.1).

### 5.7.1 Metadata Publication and Retrieval

Contexts publish their parameters to a publicly derivable routing address, enabling pre-join inspection per the legibility principle (§1). The metadata routing address is derived deterministically from the context ID:

```
metadata_routing_id = SHA-256(context_id || "scp-metadata")
```

Published metadata includes: name, description, capability ceiling, ceiling policy, governance mode, TTL, memory scope, context mode, roles, and membership requirements. This is the same parameter set listed in §5.7, serialized as a signed metadata record by the context creator (or governance delegate).

Prospective members retrieve context parameters by subscribing to the `metadata_routing_id` on the relay without joining the context. The metadata record is signed by a current context admin, enabling verification of authenticity without membership. This makes the legibility guarantee mechanical — any identity with the context ID can derive the metadata address and inspect the context's parameters before deciding whether to join.

Metadata updates (e.g., member count changes, governance-driven ceiling modifications in `governed` contexts) are republished to the same routing address. Relays treat metadata records as standard relay messages — no special relay-side logic is required.

## 5.8 Context Identity

Contexts are cryptographic entities. You opt into a key, not a name. Spoofing a cryptographic identity is hard; spoofing a name is a UI problem for clients to solve.

Human-readable addressing (§22) adds a protocol-level resolution layer — discovery context handles, petnames, attestation-backed handles, and domain handles — that maps human-readable strings to context IDs and DIDs. Handles are resolution hints; the cryptographic context ID remains canonical. Each resolution result carries a trust level (§22.7) indicating the strength of the name-to-identifier binding.

## 5.9 Governance

Contexts support multiple governance models for who can change roles, settings, membership, and other context configuration. Models include but are not limited to: single admin, multi-sig (N-of-M approval), elected moderators, full member consensus, weighted voting.

The governance model is declared at creation and visible to all. Governance implementations are **pluggable** — the protocol defines the `GovernanceEngine` trait (propose, approve, reject) with four concrete models: `SingleAdmin` (single-admin authority), `Threshold` (M-of-N approval), `Majority` (majority vote), and `Unanimity` (full consensus). See ADR-008 (context lifecycle state machine with single-admin governance), ADR-009 (role assignment and capability ceiling enforcement), and ADR-031 (multi-admin governance models) for full specification. Context creators select a governance model at creation; the selection is visible in context metadata (§5.7) and cannot be changed after creation unless the model itself defines a governance transition mechanism.

**Governance execution invariants.** When the `ContextManager` executes an approved governance action, two protocol-level invariants MUST hold:

1. **Proposal-context binding.** A governance proposal's `context_id` MUST match the context it is submitted to for execution. A proposal approved for context A MUST NOT be executable against context B. This prevents cross-context proposal injection — an attacker who obtains an approved proposal from one context cannot replay it against a different context.

2. **Proposal replay protection.** Each context MUST track the set of executed proposal IDs. A proposal that has already been executed MUST be rejected on subsequent submission. This prevents double-execution of approved proposals — even when the underlying operation is idempotent (e.g., blocking an already-blocked author returns `MemberNotFound`), explicit replay detection provides a clean error path and prevents side effects from re-executing event log entries or notifications.

## 5.10 Context TTL (Time-to-Live)

Contexts gain an optional time-to-live — a declared lifespan after which the context closes automatically. TTL is set at creation and visible in context metadata (visible before opt-in).

When TTL expires:

- Context is closed. No new actions are accepted.
- Encryption keys can be destroyed per the context's memory scope (§5.11), making content physically unreadable.
- **Durable data persists.** The context's existence, its metadata, its participants, and behavioral record contributions survive. Context is durable data — the interaction inside may be ephemeral, but the fact of the interaction is permanent.

TTL is useful beyond bilateral messaging. Time-boxed brainstorming sessions. Pop-up events. Temporary project groups. Scheduled context expiry for data hygiene. The extension is general-purpose.

**Extension mechanics.** TTL is set at creation. A context's TTL cannot be extended unilaterally. Extension requires agreement from all parties (for bilateral contexts) or through the context's governance model (for multi-party contexts). This prevents one party from unilaterally extending an interaction the other expected to be ephemeral. An expired TTL is final — if participants want to continue, they create a new context (which may reference the closed one for continuity).

**Promotion policy.** Contexts with a TTL also declare a **promotion policy** at creation — whether the context can transition from ephemeral to persistent. The policy is immutable (locked at creation). Two policies:

- **`no_promotion`** (default for ephemeral templates): Context expires per TTL. To continue, create a new context referencing the closed one. Cleanest security model — separate context IDs, separate key material, clear event log boundary.
- **`promotable`**: Context can be promoted to persistent via governance. On promotion: TTL is removed, memory scope transitions from ephemeral to full, existing event log and key material are preserved. Promotion requires consent from **all current members** (not just governance approval) because promotion changes the opt-in contract.

The promotion policy is visible in context metadata (§5.7) before opt-in.

**Interaction with governance.** Governance actions on a TTL'd context follow the same rules as any context — but the TTL acts as a hard upper bound. A governance proposal to extend TTL is valid and follows the context's governance model, but the extension requires explicit consent from all current members (not just governance approval) because TTL was part of the original opt-in contract.

**Key destruction on expiry.** When TTL expires, key destruction follows the memory scope (§5.11). The destruction protocol includes platform-attested verification where available — see §9.15 for the ephemeral key destruction verification mechanism.

## 5.11 Memory Scope

Contexts gain a declared memory scope — what happens to the context's data when it closes or expires. Memory scope is set at creation and visible in context metadata (visible before opt-in).

Three scopes:

**Ephemeral.** Context encryption keys are destroyed on close AND the SDK issues deletion requests to relays for all encrypted event data associated with the context. Content is physically unreadable (keys destroyed) and actively cleaned up (ciphertext deleted where relays comply). Durable metadata persists: who participated, when, the declared purpose, behavioral contributions (participation counts, tool invocations), and discovery provenance. An agent's local orchestration (above the protocol boundary) may retain information from the interaction, but any data the agent subsequently uses elsewhere carries provenance at the protocol level: "sourced from closed ephemeral context."

Relay deletion is best-effort — relays are untrusted infrastructure and cannot be forced to delete. Defense in depth: even if a relay retains the encrypted blobs, the keys are destroyed and the data is unreadable. Relay compliance with deletion requests is tracked as part of relay reliability scoring (§9.9.2) — relays that retain data they were asked to delete are scored lower and deprioritized for future context creation.

**Summary.** Context produces a structured summary on close. Full content is destroyed (keys destroyed as with ephemeral). The summary persists with full provenance. Both parties can verify the summary against the event log before keys are destroyed. The summary format is defined by the context (via tools or governance), not by the protocol — the protocol provides the lifecycle hooks (pre-close summary generation, verification window, key destruction) but does not prescribe summary content.

**Full.** Standard behavior. Context persists indefinitely. No memory restrictions. Content remains accessible to members. This is the default when no memory scope is specified.

**Broadcast context memory scope.** Broadcast contexts support `Full` memory scope only. Ephemeral and Summary scopes require MLS group state destruction for forward secrecy guarantees — broadcast contexts do not have MLS group state. Broadcast key destruction on context close is still performed, but without MLS epoch-based forward secrecy, the security properties of Ephemeral/Summary are weaker. Future protocol versions may define broadcast-specific ephemeral semantics; v1 restricts broadcast to Full scope.

**The Moltbook defense.** Memory scope + provenance tagging (§7.7) prevents time-shifted prompt injection — the attack pattern where malicious payloads are planted in one interaction and activate in a later interaction:

- Ephemeral contexts destroy the source material at the protocol level
- Any data that survives (in agent local memory above the protocol boundary) carries provenance when reintroduced to the protocol: "this came from context X with agent Y"
- Other participants see the provenance and evaluate accordingly
- Fragmented payloads can't reassemble undetected across interactions because each fragment's origin is traceable

**Enforcement honesty.** The protocol enforces memory scope through cryptographic key destruction — specifically, MLS group state destruction (tree secrets, all epoch key schedules, application key material). This is verifiable and absolute for protocol-level data. Platform-attested destruction (§9.15) provides hardware-backed evidence that keys were deleted where available. However, the protocol cannot enforce memory scope above the protocol boundary. An agent's underlying model may retain information from an ephemeral interaction in its own memory. The spec is explicitly honest about this limitation: ephemeral memory scope destroys the protocol-level record and makes reproduction unverifiable, but does not guarantee the agent has forgotten. The absence of provenance on information an agent produces from memory is itself a signal — "this data has no verified origin." Participants in other contexts can evaluate unprovenanced information accordingly.

## 5.12 Context Templates and Lightweight Creation

Context creation requires specifying a ceiling, roles, governance model, memory scope, TTL, and tools. For durable, bespoke contexts this is appropriate — the creator is designing a space. But contexts must also be cheap and disposable. If "spin up a quick context" requires manual configuration of six parameters, agents will route around the protocol for lightweight coordination. Context templates solve this.

### 5.12.1 Well-Known Templates

The protocol defines a set of well-known templates — named parameter bundles with fixed, predictable configurations. Templates are protocol-level identifiers, not SDK convenience wrappers. Both the creator and the joining party recognize the template ID and know exactly what it means without inspecting individual parameters.

```
Template: "scp:template/bilateral-ephemeral"
  ceiling:     [messagesRead, messagesWrite]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: ephemeral
  ttl:         required (creator sets duration, no default — forces intentionality)
  tools:       none

Template: "scp:template/bilateral-persistent"
  ceiling:     [messagesRead, messagesWrite]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: full
  ttl:         none
  tools:       none

Template: "scp:template/coordination"
  ceiling:     [messagesRead, messagesWrite, toolInvokeAll]
  roles:       [admin (creator), member (joiner)]
  governance:  single-admin
  memory_scope: summary
  ttl:         required (creator sets duration)
  tools:       creator-defined at creation

Template: "scp:template/group-discussion"
  ceiling:     [messagesRead, messagesWrite, memberInvite]
  roles:       [admin, member, observer]
  governance:  single-admin
  memory_scope: full
  ttl:         optional
  tools:       none

Template: "scp:template/public-broadcast"
  mode:          Broadcast
  ceiling:       [messagesRead, messagesWrite, toolRegister, toolInvokeAll]
  roles:
    owner:       all capabilities in ceiling + memberInvite, roleAssign, contextClose
    author:      messagesWrite, messagesRead, toolInvokeAll
    subscriber:  messagesRead (auto-granted on DID-authenticated registration)
  governance:    single-admin
  memory_scope:  full
  ttl:           optional

Template: "scp:template/gated-broadcast"
  mode:          Broadcast
  ceiling:       [messagesRead, messagesWrite, toolRegister, toolInvokeAll]
  roles:
    owner:       all capabilities in ceiling + memberInvite, roleAssign, contextClose
    author:      messagesWrite, messagesRead, toolInvokeAll
    subscriber:  messagesRead (requires admin-issued UCAN)
  governance:    single-admin
  memory_scope:  full
  ttl:           optional

Template: "scp:template/tool-interface"
  ceiling:       [messagesRead, messagesWrite, toolRegister, toolInvokeAll]
  roles:         [admin (creator), member (joiner)]
  governance:    single-admin
  memory_scope:  full
  ttl:           optional
  tools:         creator-defined at creation

Template: "scp:template/paid-service"
  ceiling:       [messagesRead, messagesWrite, toolRegister, toolInvokeAll]
  ceiling_policy: immutable
  roles:         [admin (creator), member (joiner)]
  governance:    single-admin
  memory_scope:  full (receipts are provenance)
  economic_policy: required — per_tool_invoke must be set at creation
  extends:       scp:template/tool-interface
  ttl:           optional

Template: "scp:template/paid-broadcast"
  mode:          Broadcast
  ceiling:       [messagesRead, messagesWrite]
  ceiling_policy: immutable
  roles:
    owner:       all capabilities in ceiling + memberInvite, roleAssign, contextClose
    author:      messagesWrite, messagesRead
    subscriber:  messagesRead (requires admin-issued UCAN, granted after payment verification)
  governance:    single-admin
  memory_scope:  full
  economic_policy: required — per_period must be set at creation
  extends:       scp:template/gated-broadcast
  ttl:           optional
```

The ONLY difference between `public-broadcast` and `gated-broadcast` is whether the subscriber role's `messagesRead` is auto-granted (DID-authenticated, following the discovery context reader-tier pattern §6.2.2B) or requires an explicit admin-issued UCAN (like encrypted context membership). The open/gated distinction is expressed through the template's role definitions, not through a new enum type.

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
  | discovery_context // DID is registered in a discovery context I trust
```

Example policy: "Auto-accept `bilateral-ephemeral` contexts from any DID I share at least one context with, if TTL ≤ 10 minutes, at most 5 per hour."

**Security properties:**
- Policies never auto-accept contexts with tool capabilities (ceiling containing `toolInvoke*`). Tool access always requires explicit confirmation. This is non-overridable.
- Rate limiting prevents a compromised contact from flooding auto-accepts.
- The `shared_context` trust requirement means strangers can never trigger auto-accept — the existing shared context provides the trust baseline.
- Auto-accept policies are enforced in the SDK, not the protocol. The protocol sees a normal context join. The policy just determines whether the SDK prompts the human or acts autonomously.

**No auto-accept for tool-bearing contexts.** This is a hard rule, not a default. Any context whose ceiling includes `toolInvokeAll`, `toolInvokeSpecific`, or any tool-related capability requires explicit human or agent confirmation regardless of auto-accept policies. The rationale: tool access is the capability that enables cross-context data flow (§6.2). Auto-accepting it would silently expand the agent's cross-context attack surface.

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
  ceiling: [messagesRead, messagesWrite],
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

2. Standing channels are immediately available.
   Messages sent before transport reconnects are queued locally.
   Messages received while offline are retrieved from relay on reconnect.
```

**During operation — contexts are created and destroyed fluidly:**

```
Agent lifecycle                              Context operations
──────────────────────────────────────────────────────────────────

Receives task: "coordinate with Bob"
  └── sdk.standing_channel(bob_did)          [get-or-create, ~0ms or ~200ms]
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

**Key property: contexts survive process restarts.** Context state (MLS group state, sender keys, event log position) is persisted to secure storage on every state transition (ADR-008). When the application restarts, all Active contexts are restored and transport is reconnected. No re-creation, no re-invitation, no re-negotiation. This is why standing channels work — they persist across application sessions, device reboots, and network interruptions.

**Contexts are not connections.** A TCP connection dies when the process exits. A context does not. A context is a durable cryptographic group that happens to use connections for transport. The transport layer is replaceable (§8, ADR-012) and reconnectable. The context is the stable entity; the transport is ephemeral plumbing underneath.

### 5.12.6 The Contact Graph

Agents that coordinate regularly maintain **standing bilateral contexts** — the agent's contact graph. A standing channel is a `bilateral-persistent` context with no TTL, created once and kept alive for the duration of the relationship.

**Lifecycle of a standing channel:**

```
Relationship stage        Protocol action                Cost
──────────────────────────────────────────────────────────────────
First contact             create_context + invitation    ~200ms (one-time)
Ongoing communication     send/receive in context        <100ms per message
Idle period               nothing (context persists)     0 (no keepalive)
Reconnect after offline   transport reconnect            background, automatic
Relationship ends         close_context                  one-time, keys preserved or destroyed per memory scope
```

**Standing channels have zero idle cost.** No keepalives, no heartbeats, no periodic key rotation (MLS key updates happen on message send, not on a timer). An agent with 500 standing channels and no active conversations uses zero network bandwidth. The only cost is local storage for persisted MLS state — approximately 2-5KB per bilateral context (two-leaf ratchet tree, sender key material, minimal event log metadata).

**Standing channels vs. ephemeral contexts — when to use which:**

| | Standing channel | Ephemeral context |
|---|---|---|
| Template | `bilateral-persistent` | `bilateral-ephemeral` |
| TTL | None (lives indefinitely) | Required (forces intentionality) |
| Memory scope | Full (history preserved) | Ephemeral (keys destroyed on close) |
| Use case | Ongoing relationship, general communication | Bounded task, sensitive negotiation, time-boxed coordination |
| Analogy | Phone contact | Phone call |
| Creation | Once per relationship | Once per interaction |

An agent typically has a standing channel with every peer it communicates with regularly, and creates ephemeral contexts on top of that for specific bounded tasks — especially tasks involving sensitive data that should not persist.

**First-contact optimization.** When two agents already share a context (e.g., both are members of a group), creating a standing channel between them is faster: both agents already have each other's DID documents and MLS key packages cached from the shared context. The SDK SHOULD use this cached key material to skip DID resolution, reducing first-contact setup to a single relay roundtrip.

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
Parent A ceiling: [messagesRead, messagesWrite, toolInvokeAll, media]
Parent B ceiling: [messagesRead, messagesWrite, toolInvokeAll]

Child ceiling ≤ intersection = [messagesRead, messagesWrite, toolInvokeAll]
```

The child's ceiling can be equal to or narrower than the intersection — never broader. A child that only needs messaging can declare `[messagesRead, messagesWrite]` even if the intersection would allow tools.

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

2. **Relay-level validation.** Relay infrastructure independently validates eligibility constraints on child context creation messages and membership addition messages. The relay verifies that (a) the child's declared ceiling is a subset of the intersection of all parent ceilings, and (b) each member being added is present in at least one parent context's membership roster. Relay-side validation is independent of SDK behavior — a non-compliant SDK that attempts to create a child context violating parent ceiling constraints or add ineligible members will have its messages rejected by the relay. This makes eligibility enforcement a protocol-level guarantee, not an SDK honor system.

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
  ceiling: [messagesRead, messagesWrite],
  ttl: .hours(2)
)
→ A's governance approves (Alice has contextCreate capability in A)
→ B's governance approves (Alice has contextCreate capability in B)
→ Child C created
```

**B. Coordinated creation across contexts.** Alice is in A with creation rights. Bob is in B with creation rights. Neither is in the other's context. They coordinate (via a bilateral context, shared context, or out-of-band) to create child C.

Coordination uses an intrinsic tool call available within each context's governance. Alice invokes the child-creation tool in A with the proposed child params and the list of co-parents. A's governance evaluates and, if approved, publishes a **child creation proposal** — a signed, content-addressed record of the approved params. Bob does the same in B. The protocol matches proposals by their content hash: when all proposed parents have published matching proposals (identical child params), the child is created. Proposals expire after a configurable timeout (suggested default: 1 hour).

```
Alice (in A) → invokes child creation tool → A's governance approves
             → A publishes proposal { hash(child_params), parent_list, approval_sig }
Bob (in B)   → invokes child creation tool → B's governance approves
             → B publishes proposal { hash(child_params), parent_list, approval_sig }
Protocol matches proposals by content hash
→ Child C created
→ Both Alice and Bob are initial members
```

This reuses the existing tool call model — no new protocol primitive. The child creation tool is intrinsic to contexts that include the `childContextCreate` capability in their ceiling.

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

**Standing channels.** A standing channel (§5.12.6) between Alice and Bob can be modeled as a multi-parent child of whatever context(s) Alice and Bob share. This is not required — standing channels remain lightweight bilateral contexts that work without nesting. But if structural governance over the standing channel is desired (a parent context's governance should have authority over the channel), nesting provides that.

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

**Auto-accept policies.** Auto-accept policies (§5.12.2) can be extended to cover child context invitations. A policy might specify: "auto-accept invitations to children of contexts I'm already in, with ceiling ≤ [messagesRead, messagesWrite], TTL ≤ 10 minutes." The parent lineage provides a stronger trust signal than a standalone context invitation — the member knows the child is governed by contexts they already participate in.

**Mixed-mode nesting.** A child context may have a different `ContextMode` than its parents. A Broadcast child of Encrypted parents enables public read access to curated content from a private group. An Encrypted child of Broadcast parents enables private discussion among subscribers. Ceiling inheritance (§5.13.1) and eligibility enforcement (§5.13.2) operate identically regardless of mode — they are structural properties, not encryption properties. The child's mode is declared at creation and visible in metadata.

### 5.13.8 Nesting Depth

The protocol enforces a maximum nesting depth (suggested default: 3 levels). A child of a child of a child is permitted; a fourth level is rejected. This bounds:

- Governance complexity (each level adds configurable permissions)
- Ceiling reduction (each level can only narrow, so deep nesting converges on empty ceilings)
- Lifecycle cascade depth (closing a grandparent cascades through children and grandchildren)
- Trust evaluation complexity (provenance with deep nesting lineage is harder to evaluate)

The nesting depth limit is a protocol constant, not configurable per context. It applies to the longest path from any root ancestor to the context being created.

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

**Key lifecycle:**

1. Author generates initial broadcast key (epoch 0) on role grant.
2. Normal operation: encrypt content with current key.
3. On block: increment epoch, generate new key, publish `KeyEpochAdvance` notification.
4. Subscriber requests new key → author checks block list → responds with HPKE-encrypted key or ignores.
5. On unblock: author can redistribute key to previously blocked DID on their next request.

**Key derivation:** New keys on rotation are freshly generated random 32-byte AES-256 keys (not HKDF-derived from a master secret). This provides key independence — compromise of one epoch's key reveals nothing about other epochs.

### 5.14.3 Subscriber Registration

Broadcast contexts reuse the two-tier membership model from discovery contexts (§6.2.2B):

- **Writer tier (authors):** Hold `messagesWrite` UCAN. Bounded. Manage content and key distribution.
- **Reader tier (subscribers):** DID-authenticated (open) or UCAN-authenticated (gated). Unbounded. Receive author broadcast keys on request.

Subscribers register via DID-signed requests — the same pattern discovery context readers use:

```rust
pub struct SubscriberRegistration {
    pub subscriber_did: DID,
    pub wrapping_pubkey: X25519PublicKey,
    pub ucan: Option<UcanToken>,   // Required for gated contexts (messagesRead UCAN)
    pub timestamp: u64,
    pub signature: Ed25519Signature,
}
```

- Published to the context's `routing_id` as a structured relay message.
- Author SDKs process registrations, respond with current broadcast key via the pull-based key protocol.
- Event log records registration via `MemberJoined` with role `subscriber`.

### 5.14.4 Open vs. Gated Broadcast

The distinction between open and gated broadcast is expressed through the existing role/UCAN system at the template level, not through a new enum:

**Open broadcast** (`public-broadcast` template): The subscriber role's `messagesRead` capability is granted on DID-authenticated registration — no admin-issued UCAN required. This mirrors discovery context readers who query via DID-signed requests without UCAN.

**Gated broadcast** (`gated-broadcast` template): The subscriber role requires an explicit `messagesRead` UCAN from the context admin. Same as encrypted context membership — capabilities require admin-issued tokens.

**Key request validation:**
- Open: author checks block list only. Not blocked → respond with key.
- Gated: author checks (1) valid `messagesRead` UCAN, (2) block list. Both pass → respond with key.

Gated contexts enable: paid subscriptions (admin grants `messagesRead` after payment verification — see §19.10 `paid-broadcast` template), invite-only communities (admin grants `messagesRead` to approved members), and tiered access (scoped UCANs for different content levels).

### 5.14.5 BroadcastEnvelope

```rust
pub struct BroadcastEnvelope {
    pub context_id: ContextId,
    pub sender_did: DID,
    pub sequence: u64,
    pub key_epoch: u64,
    pub timestamp: u64,
    pub content_hash: [u8; 32],  // SHA-256 of plaintext content
    pub content: Vec<u8>,        // AES-256-GCM encrypted with author broadcast key
    pub provenance: Option<DataProvenance>,
    pub signature: Ed25519Signature,
}
```

**Signature formula:**
```
Ed25519_sign(active_signing_key, SHA-256(
    context_id || sender_did || sequence || key_epoch || timestamp || content_hash || provenance_hash
))
```

Where `provenance_hash = SHA256(serialize(provenance))` if present, or `SHA256(0x00)` if absent (same sentinel as InnerEnvelope, ADR-002).

**Send path:** validate UCAN (`messagesWrite`) → assign sequence number → hash plaintext → hash provenance → sign → AES-256-GCM encrypt with author broadcast key → serialize → wrap in OuterEnvelope → relay PUBLISH.

**Receive path:** transport receive → dedup by blob hash → deserialize → verify signature against author's known Active Signing Key → decrypt with cached author broadcast key for this epoch → verify `content_hash == SHA-256(decrypted_content)` → verify author UCAN → replay check (sequence number) → deliver to application layer.

### 5.14.6 Routing

`routing_id = SHA-256(context_id)` — publicly derivable. Subscribers can subscribe to the relay topic, but cannot read content without author broadcast keys. This differs from encrypted context routing where `routing_id` is derived via HKDF from identity key material (§9.10.4) — broadcast contexts use a public derivation because author identity is visible in the BroadcastEnvelope (not hidden inside MLS encryption).

### 5.14.7 Membership

| Role | UCAN | Registered | Write | Read |
|---|---|---|---|---|
| Owner | Yes (full) | Yes | Yes | Yes |
| Author | Yes (`messagesWrite`) | Yes | Yes | Yes |
| Subscriber (open) | No (DID-auth only) | Yes (DID + wrapping key) | No | Yes |
| Subscriber (gated) | Yes (`messagesRead`) | Yes (DID + wrapping key + UCAN) | No | Yes |

### 5.14.8 Blocking

Author-level, cryptographic, pull-based — the same protocol as encrypted contexts (§9.16.3):

1. Author adds DID to block list, increments key epoch.
2. Publishes `KeyEpochAdvance` notification (relay message, not MLS).
3. Blocked subscriber requests new key → no response → cannot decrypt future content.
4. Non-blocked subscribers request → get HPKE-encrypted key → continue reading.

Blocking is per-author. Author A blocking a subscriber does not affect the subscriber's access to Author B's content.

**Author removal.** Removing an author from a broadcast context (revoking their sender key and preventing future publishing) is a governance-gated action. Author removal MUST go through the context's governance model (`GovernanceAction::BlockAuthor` proposal → governance approval → execution). There is no standalone API to remove an author without governance approval. This enforces the protocol tenet: "Agents are participants, not enforcers. Same rules as any human-bound participant." A direct bypass of governance for author removal would be the vulnerability, not the feature. When the governance proposal is approved and executed, the author's sender key is destroyed, `publish()` returns `PermissionDenied`, key requests for the author return `Deny`, and an `AuthorBlocked` event is emitted. Subscribers who cached the author's old key can still decrypt historical messages.

**Sybil resistance.** Broadcast contexts are the primary target for Sybil block bypass because key requests travel as relay messages (not MLS application messages). The membership gate in `handle_sender_key_request` verifies that the requester is a registered subscriber before distributing keys. Identity-linked block expansion and group blocking further mitigate Sybil attacks. See §9.16.6 for the full mitigation specification.

### 5.14.9 Capabilities

No new capability variants. `messagesWrite` and `messagesRead` apply to both Encrypted and Broadcast modes — the abstract capability to write/read in a context. `ContextMode` determines the processing pipeline.

### 5.14.9.1 Economic Policy in Broadcast Contexts

`EconomicPolicy` (§19.3) applies to broadcast contexts identically to encrypted contexts — it is a property of `ContextParams`, not of `ContextMode`. Authors pay per-message costs; subscribers pay access costs if the context uses a gated template. `SenderVelocity` (§19.7) anti-spam metrics apply per-author in broadcast mode (each author is an independent sender). The `paid-broadcast` template (§19.8) is the canonical example of economic policy applied to broadcast contexts.

### 5.14.10 Event Log

Reuses existing event types wherever possible. Only one genuinely new type:

- `MessageSent` — reused for broadcast (same event, mode determines semantics)
- `roleAssigned` — reused for author grant (role: `author`) and subscriber registration (role: `subscriber`)
- `MemberJoined` — reused for subscriber registration
- `TokenRevoked` — reused for gated subscriber revocation
- **`AuthorBlocked { author_did }`** — emitted when a governance-approved author removal executes. The author's sender key is destroyed. Distinct from `TokenRevoked` (which has different semantics: UCAN revocation).
- **`KeyEpochAdvance { sender_did, epoch }`** — NEW event type, shared across both Encrypted and Broadcast modes

`ConsistencyCheckpoint.epoch` becomes `Option<u64>` (`None` for broadcast contexts, which have no MLS epoch).

### 5.14.11 Discovery

Broadcast contexts are discoverable through four mechanisms:

1. **DID document service endpoint.** Authors MAY publish an `SCPBroadcastContext` service entry in their DID document with the context ID and relay URLs.
2. **Discovery contexts.** Authors register broadcast contexts via `agent_register` in discovery contexts (§6.2.2B), with metadata indicating the context mode.
3. **`.well-known/scp`.** Operators MAY list broadcast contexts in their `.well-known/scp` document (§18.3). Only broadcast context IDs may be listed — encrypted context IDs MUST NOT appear (§9.10 metadata privacy).
4. **Out-of-band URI.** The universal context URI format (§18.4) is used for sharing context references: `scp://context/<context_id_hex>?relay=<url>&mode=broadcast`. The legacy format `scp://broadcast/<context_id_hex>?relay=<url>` is accepted as an alias and normalized to the universal format.

### 5.14.12 Security Model Delta

Relative to Encrypted contexts, Broadcast contexts have the following security property changes:

**Retained:** Ed25519 authentication, content integrity (content_hash + signature), provenance, non-repudiation, UCAN authorization, event log, human accountability.

**Changed:** Confidentiality via per-author broadcast key (not MLS). No MLS `membership_tag` (authentication is signature-only). No MLS forward secrecy (mitigated by key epoch rotation on block events). Public `routing_id` (SHA-256 of context_id, not HKDF-derived). Author identity visible to relays in the outer envelope (authors are public figures in a broadcast context — this is a feature, not a leak).

See §9.5, §9.8, §9.9, and §9.10 for the full broadcast security analysis.
