# SCP API Design Sketch

**Status:** Early sketch — interfaces, not implementation
**Purpose:** Make the protocol tangible through concrete API surfaces and use cases

---

## 1. Identity

### Create Identity

First launch. User never sees keys.

```
SCP.Identity.create(
  custody: .secureEnclave | .passkey | .platform(apple|google) | .selfManaged,
  recovery: [.trustedDevice, .socialRecovery, .platformBacked]
) → Identity { did, publicKey, custodyMethod }
```

### Authenticate

Resolves any auth method to a DID.

```
SCP.Identity.authenticate(
  method: .passkey | .biometric | .platformSSO
) → AuthenticatedSession { did, sessionToken }
```

### Link Existing Identity

Optional. Convenience, not source of truth.

```
SCP.Identity.link(
  did: myDID,
  platform: .apple(token) | .google(token) | .github(token)
) → LinkedIdentity { did, linkedPlatforms[] }
```

### Recovery

```
SCP.Identity.recover(
  method: .trustedDevice(approvalFromDeviceID)
        | .social(approvals: [DID])
        | .platform(apple|google)
) → Identity
```

---

## 2. Contexts

### Create

```
SCP.Context.create(
  creator: Identity,
  ceiling: [Capability],           // max permissions this context can ever grant
  governance: .singleAdmin
            | .multiSig(threshold: Int, admins: [DID])
            | .consensus
            | .custom(GovernanceModel),
  tools: [ToolDefinition],
  roles: {
    "admin":    [Capability],
    "member":   [Capability],
    "observer": [Capability],
    ...custom
  },
  metadata: {
    name: String,                  // display only, client concern
    description: String,
    public: Bool                   // discoverable vs invite-only
  }
) → Context { contextID, creatorDID, ceiling, roles, governance }
```

### Inspect (before opt-in)

Anyone can read this. This is the "what am I walking into" view.

```
SCP.Context.inspect(
  contextID
) → ContextMetadata {
  contextID,
  ceiling: [Capability],
  roles: { name: [Capability] },
  governance: GovernanceModel,
  creator: DID,
  memberCount: Int,
  age: Date,
  tools: [ToolMetadata]            // name, description, input/output schema
}
```

### Join

```
SCP.Context.join(
  context: contextID,
  as: Identity,
  agentMetadata: AgentCapabilityProfile
) → Membership { contextID, did, role, capabilityTokens[] }
```

Returns the role assigned (non-negotiable) and UCAN tokens scoped to this context.

### Leave

```
SCP.Context.leave(
  context: contextID,
  as: Identity
) → void
```

### List

```
SCP.Context.list(
  for: Identity,
  filter: .all | .created | .member | .observer
) → [ContextSummary]
```

---

## 3. Agents (within a context)

### Register Agent

When joining a context, your agent is instantiated. One per person per context.

```
SCP.Agent.register(
  context: contextID,
  identity: Identity,
  metadata: AgentCapabilityProfile {
    capabilities: [String],        // functional profile, not model name
    version: String
  }
) → AgentInstance { agentID, contextID, did, role, tokens[] }
```

### Agent Actions

Everything an agent does within a context flows through its membership.

```
// Send a message
agent.send(
  content: MessageContent,
  attachments: [Attachment]?
) → MessageReceipt

// Invoke a context tool
agent.invoke(
  tool: "recipe_assistant",
  input: { "query": "butter substitute" }
) → ToolResult

// Read context state
agent.read(
  resource: .members | .messages(since:) | .toolList | .metadata
) → Resource
```

Every action is validated: does this agent's role in this context grant the required capability? Is the capability token valid and unrevoked?

---

## 4. Tools (within a context)

### Define

Tools are stateless functions. Registered at context creation or added by admin.

```
SCP.Tool.define(
  name: "recipe_assistant",
  description: "Answers cooking questions",
  input: Schema {
    query: String,
    cuisine: String?,
    dietary: [String]?
  },
  output: Schema {
    answer: String,
    sources: [URL]?
  },
  requiredRole: "member"           // minimum role to invoke
)
```

### Invoke

```
SCP.Tool.invoke(
  context: contextID,
  agent: agentID,                  // who's calling (validated against role)
  tool: "recipe_assistant",
  input: { query: "butter substitute" }
) → ToolResult { output, provenance }
```

Provenance is attached automatically: which context, which agent invoked, timestamp, input hash.

### Cross-Context Tool Interface

Both contexts opt in. Calls are stateless.

```
// Context A exposes a tool to Context B
SCP.ToolInterface.expose(
  from: contextA,
  tool: "ingredient_database",
  to: contextB,
  permissions: .readOnly
) → InterfaceID

// Context B invokes it
SCP.ToolInterface.call(
  interface: interfaceID,
  agent: agentInContextB,          // must have permission in B to use interfaces
  input: { search: "miso paste" }
) → ToolResult { output, provenance: { originContext: contextA, interface: interfaceID } }
```

---

## 5. Trust & Capabilities

### Grant Capability

A human grants their agent specific capabilities for a specific context.

```
SCP.Capability.grant(
  from: Identity,
  to: agentID,
  context: contextID,
  capabilities: [.messaging, .toolInvocation("recipe_assistant"), .invite],
  expiry: Date?,
  constraints: { maxInvocationsPerHour: 100 }?
) → UCANToken
```

### Revoke

Granular. Per-capability, per-agent, per-context.

```
SCP.Capability.revoke(
  token: UCANToken
) → void

// Or revoke everything for an agent
SCP.Capability.revokeAll(
  agent: agentID,
  context: contextID
) → void

// Nuclear: revoke all capabilities for a DID across all contexts
SCP.Capability.revokeIdentity(
  did: DID
) → void
```

### Evaluate Trust

When your agent encounters another agent.

```
SCP.Trust.evaluate(
  subject: AgentPresentation {
    did: DID,
    agentProof: Signature,
    capabilityTokens: [UCANToken],
    agentMetadata: AgentCapabilityProfile
  },
  myRelationship: RelationshipData?,     // from your local social graph
  context: contextID
) → TrustEvaluation {
  identity: DID,
  verifiedCapabilities: [Capability],
  agentProfile: AgentCapabilityProfile,
  relationship: RelationshipSummary?,
  // your agent/client decides what to do with this
}
```

This is not a binary "trust/don't trust" — it returns the data your agent needs to make a contextual decision.

---

## 6. Governance

### Propose Change

Context settings changes go through governance.

```
SCP.Governance.propose(
  context: contextID,
  proposer: agentID,
  change: .addTool(ToolDefinition)
        | .removeTool(toolName)
        | .modifyRole(name, [Capability])
        | .addRole(name, [Capability])
        | .removeMember(DID)
        | .changeGovernance(GovernanceModel)
) → Proposal { proposalID, requiredApprovals, deadline }
```

### Approve / Reject

```
SCP.Governance.approve(proposalID, by: agentID) → ProposalStatus
SCP.Governance.reject(proposalID, by: agentID) → ProposalStatus
```

Resolution depends on governance model: single admin auto-approves, multi-sig waits for threshold, consensus waits for all members.

---

## 7. Use Cases Mapped to APIs

### Cronica: User Creates a Quest

```swift
// 1. Create quest as context
let quest = try await SCP.Context.create(
  creator: alice,
  ceiling: [.messaging, .media, .toolInvocation, .progressTracking],
  governance: .singleAdmin,
  tools: [guideAssistant, stepTracker, mediaUpload],
  roles: [
    "admin": [.all],
    "member": [.messaging, .toolInvocation, .media, .progressTracking],
    "guide": [.messaging, .toolInvocation, .suggestSteps]
  ],
  metadata: { name: "Learn to Cook Thai Food", public: true }
)

// 2. Cronica's AI Guide joins with "guide" role
try await SCP.Context.addMember(
  context: quest.contextID,
  identity: chronicaGuide,       // Cronica's institutional DID
  role: "guide"
)

// 3. Alice's agent invokes the guide
let advice = try await alice.agent.invoke(
  tool: "guide_assistant",
  input: { query: "where do I start with Thai cooking?" }
)
```

### Cronica: Someone Joins a Quest Community

```swift
// 1. Bob inspects before joining
let meta = try await SCP.Context.inspect(questContextID)
// Bob sees: ceiling, his role would be "member", tools available, 
// 47 members, created 3 weeks ago, Alice is creator

// 2. Bob joins
let membership = try await SCP.Context.join(
  context: questContextID,
  as: bob,
  agentMetadata: bobAgent.profile()
)
// Bob gets member role, UCAN tokens for member capabilities

// 3. Bob's agent participates
try await membership.send(content: "Just made my first green curry!")
let tips = try await membership.invoke(
  tool: "guide_assistant",
  input: { query: "my curry is too watery, help" }
)
```

### Generated Client: Custom Quest App

```swift
// Same identity, same contexts, different client
let session = try await SCP.Identity.authenticate(method: .passkey)

// All of Alice's contexts are immediately available
let myQuests = try await SCP.Context.list(
  for: session.identity,
  filter: .all
)
// This returns the same contexts whether Alice is on Cronica,
// a generated client, or a CLI tool

// Generated client adds a calendar tool to a quest
try await SCP.Governance.propose(
  context: myQuestID,
  proposer: alice.agentID,
  change: .addTool(calendarSync)       // Alice is admin, auto-approves
)

// Calendar tool now available in this context
// Bob on Cronica won't see a calendar UI, but the tool exists
// His client could surface it if it knew how
```

### Cross-Context: Quest Uses External Knowledge Base

```swift
// A cooking school runs a recipe database as a context with tools
// Alice's quest context wants access to it

// 1. Cooking school exposes their tool
let interface = try await SCP.ToolInterface.expose(
  from: cookingSchoolContext,
  tool: "recipe_database",
  to: aliceQuestContext,
  permissions: .readOnly
)

// 2. Alice's agent in her quest can now query it
let recipes = try await SCP.ToolInterface.call(
  interface: interface.id,
  agent: alice.agentInQuest,
  input: { search: "green curry", difficulty: "beginner" }
)
// Result carries provenance: originated from cooking school context
```

### Blocking a Bad Actor

```swift
// Dave is spamming multiple quest communities

// 1. Alice blocks Dave in her quest (context-level)
try await SCP.Context.removeMember(
  context: aliceQuest,
  did: dave.did
)

// 2. If Dave's behavior is systemic, Alice can block at identity level
try await SCP.Trust.block(
  did: dave.did,
  scope: .allMyContexts              // Dave's agent removed from every context Alice governs
)

// 3. Dave's DID is now flagged across Alice's trust evaluations
// Other context creators can see Dave has been blocked by N identities
// (behavioral signal, not automatic ban)
```

---

## 8. Wire Format Sketch

What actually moves on the network.

### Agent Action Message

```json
{
  "protocol": "scp/1.0",
  "type": "agent_action",
  "from": {
    "did": "did:key:z6Mkf5rG...",
    "context_agent": "agent:z6Mkf5rG:ctx:z6Mkq8...",
    "capability_token": "eyJhbGciOiJFZERTQSIs..."
  },
  "context": "did:scp:ctx:z6Mkq8...",
  "action": {
    "type": "tool_invoke",
    "tool": "recipe_assistant",
    "input": {
      "query": "butter substitute in cookies"
    }
  },
  "timestamp": "2026-02-14T15:30:00Z",
  "nonce": "a1b2c3d4",
  "signature": "z3hR9xK..."
}
```

### Context Metadata Response

```json
{
  "protocol": "scp/1.0",
  "type": "context_metadata",
  "context": "did:scp:ctx:z6Mkq8...",
  "ceiling": ["messaging", "media", "tool_invocation", "progress_tracking"],
  "governance": {
    "model": "single_admin",
    "admin": "did:key:z6MkpT..."
  },
  "roles": {
    "admin": { "capabilities": ["*"] },
    "member": { "capabilities": ["messaging", "tool_invocation", "media"] },
    "guide": { "capabilities": ["messaging", "tool_invocation", "suggest_steps"] }
  },
  "tools": [
    {
      "name": "guide_assistant",
      "description": "AI cooking guide",
      "input_schema": { "query": "string" },
      "output_schema": { "answer": "string", "sources": "string[]?" },
      "required_role": "member"
    }
  ],
  "members": 47,
  "created": "2026-01-20T10:00:00Z",
  "creator": "did:key:z6MkpT..."
}
```

### Capability Token (UCAN-shaped)

```json
{
  "header": { "alg": "EdDSA", "typ": "JWT", "ucv": "0.10.0" },
  "payload": {
    "iss": "did:key:z6MkpT...",
    "aud": "agent:z6MkpT:ctx:z6Mkq8...",
    "att": [
      { "with": "scp:ctx:z6Mkq8/tool/recipe_assistant", "can": "invoke" },
      { "with": "scp:ctx:z6Mkq8/messages", "can": "write" },
      { "with": "scp:ctx:z6Mkq8/members", "can": "read" }
    ],
    "exp": 1740000000,
    "nnc": "unique-nonce"
  },
  "signature": "..."
}
```

---

## 9. What's Not Here Yet

- Transport layer (WebSocket? Matrix? libp2p? How do messages actually move?)
- Data storage (where do context messages and state persist?)
- Media handling (how are files/images/video stored and served?)
- Offline behavior (what happens when you're disconnected?)
- Federation (how do two SCP nodes discover and talk to each other?)
- Rate limiting implementation (the surfaces are identified, enforcement is not)
- Earned capacity system (how new identities unlock more context participation)
- Protocol versioning (how SCP evolves without breaking existing contexts)
