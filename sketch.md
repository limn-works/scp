# SCP API Design Sketch

**Status:** Working sketch — interfaces, not implementation
**Purpose:** Make the protocol tangible through concrete API surfaces and use cases
**Aligned with:** spec.md (working draft, February 2026)

---

## 1. Identity

### Create Identity

First launch. User never sees keys. Device attestation proves real device.

```
SCP.Identity.create(
  custody: .secureEnclave | .passkey | .platform(apple|google) | .selfManaged,
  recovery: [.trustedDevice, .socialRecovery, .platformBacked],
  deviceAttestation: DeviceAttestation     // Apple App Attest / Google Play Integrity
) → Identity { did, publicKey, custodyMethod }
```

Device attestation binds one DID to one physical device. Sybil resistance starts here — creating identities costs the price of a device.

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

### Identity Attestations (§3.5)

Cryptographic proofs binding external platform identities to your DID. Makes bridging trustworthy and social graph import possible.

```
// Create an attestation linking your X handle to your DID
SCP.Attestation.create(
  type: .identityLink,
  issuer: myDID,
  subject: myDID,
  claim: { platform: "x", handle: "@alice" },
  evidence: .oauth(token) | .signedPost(url) | .dns(record)
) → Attestation { id, type, issuer, subject, claim, evidence, signature }

// Verify someone else's attestation
SCP.Attestation.verify(
  attestation: bobsAttestation
) → VerificationResult {
  signatureValid: Bool,
  evidenceValid: Bool,        // automated where possible
  expired: Bool,
  revoked: Bool
}

// Revoke your own attestation
SCP.Attestation.revoke(
  attestationID
) → void
```

### Identity Private State (§3.7)

Encrypted personal data — block lists, preferences, graph policies. Stored on relays, encrypted to your keys, synced across your devices.

```
// Write to your private state (append-only event log)
SCP.PrivateState.write(
  did: myDID,
  event: .block(did: daveDID)
       | .mute(did: carolDID)
       | .grantGraphVisibility(to: bobDID, scope: .thisContext(contextID))
       | .setPreference(key: "notifications", value: .minimal)
       | .annotate(did: bobDID, note: "Met at cooking class")
) → void

// Read current state (computed from event log)
SCP.PrivateState.read(
  did: myDID,
  query: .blockList | .muteList | .graphPolicies | .preferences | .all
) → PrivateStateView { ... }

// State syncs across devices automatically — append-only log,
// commutative operations, Merkle root for integrity
```

### Social Graph (§3.6)

Not a stored data structure. The social graph is computed from context membership and accessed through permission-gated protocol query APIs. These are not static methods — every query is scoped by the requester's permissions and capability grants.

```
// Query your own social graph (assembled from contexts you're in)
SCP.SocialGraph.query(
  did: myDID,
  filter: .allConnections | .sharedContexts(with: bobDID) | .contextMembers(contextID)
) → SocialGraphView {
  connections: [{
    did: DID,
    sharedContexts: Int,
    roles: [Role],
    // strength derived from shared participation
  }]
}

// Grant someone visibility into your graph
SCP.SocialGraph.grantVisibility(
  from: myDID,
  to: bobDID,
  scope: .fullContextList
       | .specificContext(contextID)
       | .connectionCount
       | .mutualConnectionsOnly
) → CapabilityToken

// Query someone else's graph (requires their grant)
SCP.SocialGraph.query(
  did: bobDID,
  asRequestor: myDID,
  token: visibilityToken
) → SocialGraphView   // scoped to what the grant allows
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
  admissionRequirements: {         // sybil resistance thresholds
    minAccountAge: Duration?,
    minContextHistory: Int?,       // participated in N contexts
    requiredAttestations: [AttestationType]?,
    endorsements: { count: Int, independent: Bool }?
  }?,
  consequenceRules: [ConsequenceRule]?,  // automated behavioral enforcement
  ttl: Duration?,                  // optional lifespan (§5.10)
  onExpiry: .close                 // close context, handle keys per memoryScope
          | .archiveMetadata,      // close + preserve metadata summary
  memoryScope: .ephemeral          // destroy keys on close (§5.11)
             | .summary            // produce summary, then destroy keys
             | .full,              // standard — persist indefinitely (default)
  metadata: {
    name: String,                  // display only, client concern
    description: String,
    public: Bool                   // discoverable vs invite-only
  }
) → Context { contextID, creatorDID, ceiling, roles, governance, ttl?, memoryScope }
```

TTL and memory scope are optional. When omitted, TTL defaults to none (context persists until manually closed) and memory scope defaults to `.full`.

When TTL expires, the context closes automatically. Key destruction follows the memory scope:
- `.ephemeral`: encryption keys destroyed immediately. Content is physically unreadable.
- `.summary`: summary generated and verified, then keys destroyed.
- `.full`: context closes but content remains accessible.

In all cases, durable metadata persists: the context's existence, participants, purpose, and behavioral contributions survive.

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
  admissionRequirements: AdmissionRequirements?,
  consequenceRules: [ConsequenceRule]?,
  creator: DID,
  memberCount: Int,
  age: Date,
  tools: [ToolMetadata],          // name, description, input/output schema
  bridges: [BridgeInfo]?          // active bridge connectors, if any
}
```

### Join

```
SCP.Context.join(
  context: contextID,
  as: Identity,
  agentMetadata: AgentCapabilityProfile,
  attestations: [Attestation]?    // present attestations if context requires them
) → Membership { contextID, did, role, capabilityTokens[] }
```

Returns the role assigned (non-negotiable) and UCAN tokens scoped to this context. Admission requirements are checked mechanically — missing attestations or insufficient history = denied.

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

When joining a context, your agent is instantiated. One per person per context. The human-agent pair is the fundamental unit — agent is the human's protocol presence.

```
SCP.Agent.register(
  context: contextID,
  identity: Identity,
  metadata: AgentCapabilityProfile {
    selfAttested: {                // claimed but unverified
      capabilities: [String],
      defenses: [String]           // "prompt_injection_filtering", etc.
    },
    challengeVerified: [{          // tested and passed
      capability: String,
      verifiedBy: DID,
      verifiedAt: Date,
      challengeSuite: String
    }],
    version: String
  }
) → AgentInstance { agentID, contextID, did, role, tokens[] }
```

### Agent Actions

Everything an agent does within a context flows through its membership.

```
// Send a message
agent.send(
  content: MessageContent,         // content is agnostic — any type
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
         | .eventLog(since:)       // verifiable event history
         | .behavioralRecord(did:) // behavioral facts for a member
) → Resource
```

Every action is validated: does this agent's role in this context grant the required capability? Is the capability token valid and unrevoked?

### Challenge-Response (§7.3.4)

Verify an agent's claimed capabilities through testing.

```
// Issue a challenge to another agent
SCP.Agent.challenge(
  target: agentID,
  suite: .promptInjectionResistance | .schemaValidation | .custom(ChallengeSpec)
) → ChallengeResult {
  passed: Bool,
  testCases: Int,
  passedCases: Int,
  verifiedAt: Date
}
// Result updates target's metadata: self-attested → challenge-verified
```

---

## 4. Tools (within a context)

### Define

Tools are stateless functions. Registered at context creation or added by admin. MCP-compatible schemas.

```
SCP.Tool.define(
  name: "recipe_assistant",
  description: "Answers cooking questions",
  input: JSONSchema {              // MCP-compatible
    query: String,
    cuisine: String?,
    dietary: [String]?
  },
  output: JSONSchema {
    answer: String,
    sources: [URL]?
  },
  requiredRole: "member",
  implementationHash: ContentHash, // content-addressable ref to implementation
  testVectors: [{                  // known input-output pairs for verification
    input: { query: "Is butter dairy?" },
    expectedOutput: { answer: "Yes, butter is a dairy product.", sources: [] }
  }],
  operator: DID                    // who's accountable for this tool
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

Provenance is attached automatically: which context, which agent invoked, timestamp.

### Verify Tool Integrity (§7.3.3)

Any agent can test a tool against its registered test vectors at any time.

```
SCP.Tool.verify(
  context: contextID,
  tool: "recipe_assistant"
) → ToolVerification {
  allTestsPassed: Bool,
  testsRun: Int,
  testsPassed: Int,
  implementationHashMatches: Bool,
  verifiedAt: Date,
  verifiedBy: DID
}
```

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

### Evaluate Trust (§7 — Four-Layer Model)

When your agent encounters another agent. Returns data from all four validation layers.

```
SCP.Trust.evaluate(
  subject: AgentPresentation {
    did: DID,
    agentProof: Signature,
    capabilityTokens: [UCANToken],
    agentMetadata: AgentCapabilityProfile
  },
  context: contextID
) → TrustEvaluation {

  // Layer 1: Protocol Enforcement (mechanical, pass/fail)
  capabilityValidation: {
    tokensValid: Bool,
    signaturesValid: Bool,
    withinCeiling: Bool,
    notRevoked: Bool
  },

  // Layer 2: Behavioral Validation (verified facts)
  behavioralRecord: {
    contextsParticipated: Int,
    totalDuration: Duration,
    governanceActionsAgainst: Int,
    toolInvocations: { type: String, count: Int }[],
    roleHistory: [RoleChange],
    endorsementAccuracy: Float?    // how accurate are their endorsements
  }?,

  // Layer 3: Attestation Authenticity (verified signatures)
  attestations: [{
    type: AttestationType,
    signatureValid: Bool,
    evidenceValid: Bool?,
    fresh: Bool,                   // within renewal interval
    issuer: DID,
    claim: Claim
  }],

  // Layer 4: Trust Evaluation inputs (for agent judgment)
  endorsements: [{
    from: DID,
    capability: String,
    endorserBehavioralRecord: BehavioralSummary
  }],
  challengeResults: [{
    capability: String,
    passed: Bool,
    verifiedAt: Date
  }],
  consequenceStructure: [ConsequenceRule]?  // context's automated rules

  // Your agent/client decides what to do with all of this.
}
```

### Attestation Operations (§7.4)

General-purpose attestation creation and verification. Common envelope, many types.

```
// Create any attestation type
SCP.Attestation.create(
  type: .identityLink | .capabilityDelegation | .toolIntegrity
      | .agentCapability | .endorsement | .roleAssignment
      | .contextEndorsement,
  issuer: DID,
  subject: DID | ToolID | ContextID,
  claim: TypeSpecificClaim,
  evidence: TypeSpecificEvidence?,
  expiry: Date?,
  renewable: Bool
) → Attestation

// Verify any attestation (same mechanics regardless of type)
SCP.Attestation.verify(attestation) → VerificationResult {
  signatureValid: Bool,
  evidenceValid: Bool?,
  expired: Bool,
  stale: Bool,                     // past renewal interval
  revoked: Bool
}

// Renew (re-verify evidence, update timestamp)
SCP.Attestation.renew(attestationID) → Attestation

// Revoke
SCP.Attestation.revoke(attestationID) → void
```

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
        | .addBridge(BridgeDefinition)
        | .removeBridge(bridgeID)
        | .modifyConsequenceRules([ConsequenceRule])
        | .modifyAdmissionRequirements(AdmissionRequirements)
) → Proposal { proposalID, requiredApprovals, deadline }
```

### Approve / Reject

```
SCP.Governance.approve(proposalID, by: agentID) → ProposalStatus
SCP.Governance.reject(proposalID, by: agentID) → ProposalStatus
```

Resolution depends on governance model: single admin auto-approves, multi-sig waits for threshold, consensus waits for all members.

---

## 7. Bridge Connectors (§12)

### Register Bridge

Bring external platform participants into an SCP context.

```
SCP.Bridge.register(
  context: contextID,
  operator: DID,                   // accountable identity running the bridge
  platform: "x" | "facebook" | "whatsapp" | "discord" | ...,
  mode: .relay | .puppet | .api | .cooperative
) → BridgeInstance { bridgeID, contextID, operator, platform, mode }
```

### Shadow Identities

External platform users represented in SCP contexts.

```
// Bridge creates a shadow identity for an external user
SCP.Bridge.createShadow(
  bridge: bridgeID,
  externalIdentity: { platform: "x", handle: "@dave" },
  attributedBy: bridgeOperatorDID
) → ShadowIdentity {
  shadowID, platform, handle, bridgeID,
  role: "observer",               // restricted by default
  provenance: .bridged(mode, operator)
}

// External user later claims their shadow with an identity attestation
SCP.Bridge.claimShadow(
  shadowID: shadowID,
  claimant: DID,
  attestation: Attestation        // identity_link matching the shadow's platform handle
) → ClaimResult {
  merged: Bool,                    // shadow retired, history attributed to claimant DID
  historicalActions: Int           // retroactively attributed
}
```

### Bridge Content Provenance

All bridged content carries provenance automatically.

```
// Bridged message carries:
BridgedMessage {
  content: ...,
  provenance: {
    source: .bridge(bridgeID),
    platform: "x",
    operator: DID,
    mode: .relay,
    attribution: .shadow(shadowID) | .claimed(DID),
    trustLevel: .native | .nativeBridged | .claimedShadow | .unclaimedShadow
  }
}
```

---

## 8. App Interface (§8.4)

### Capability Declaration

Generated or traditional apps declare what they need. The protocol provides it.

```
SCP.App.declare(
  manifest: AppManifest {
    name: "Thai Cooking Quest",
    version: "1.0",
    protocolVersion: "scp/1.0",
    requiredCapabilities: [
      .messaging,
      .memberList,
      .toolInvocation(["guide_assistant", "step_tracker"]),
      .media(.images, .video),
      .contextMetadata
    ],
    optionalCapabilities: [
      .toolInvocation(["calendar_sync"]),
      .crossContextInterface
    ]
  },
  context: contextID,
  agent: agentID
) → AppSession {
  granted: [Capability],           // what the protocol provided
  denied: [Capability],            // what exceeded role or ceiling
  interfaces: {                    // ready-to-use protocol interfaces
    messaging: MessagingInterface,
    tools: { name: ToolInterface },
    members: MemberListInterface,
    ...
  }
}
```

The declaration contract is the primary surface for generated apps. An LLM generating a client declares what it needs; the SDK handles identity, encryption, trust, transport.

### MCP Compatibility (§8.5)

The SCP agent is an MCP server locally. Models don't know about SCP.

```
// From the AI model's perspective (MCP):
mcp.tools.list() → [
  { name: "context_a/send_message", inputSchema: {...} },
  { name: "context_a/guide_assistant", inputSchema: {...} },
  { name: "context_b/schedule_meeting", inputSchema: {...} }
]

mcp.tools.call("context_a/guide_assistant", { query: "butter substitute" })
→ { answer: "...", sources: [...] }

// The agent handles everything SCP-specific:
// - Resolves context_a → contextID
// - Validates capability token
// - Encrypts the call with context key
// - Signs with DID
// - Routes through transport
// - Decrypts response
// - Returns plain result to model
```

What the model sees vs what the agent does:

```
Admin's model sees:               Member's model sees:
  context_a/send_message            context_a/send_message
  context_a/guide_assistant         context_a/guide_assistant
  context_a/admin_panel             (admin_panel not exposed)
  context_a/invite_member           (invite not exposed)
```

Capability filtering at the agent means the model never even knows about tools it can't access.

---

## 9. Verifiable Event Log (§7.3.1)

### Query Context History

Every context maintains a Merkle tree of protocol events.

```
SCP.EventLog.query(
  context: contextID,
  filter: .all
        | .since(Date)
        | .byActor(DID)
        | .byType(.message | .toolInvocation | .membershipChange | .roleChange
                  | .governanceAction | .toolMutation | .consequenceTriggered)
) → EventStream { events: [VerifiableEvent], merkleRoot: Hash }

// Verify a specific claim against the log
SCP.EventLog.verify(
  context: contextID,
  claim: .memberNeverEjected(did: carolDID)
       | .ceilingUnchangedSince(date)
       | .toolRegisteredBy(tool: "recipe_assistant", operator: DID)
       | .eventExists(eventID)
) → Proof { valid: Bool, merkleProof: MerkleProof }
```

---

## 10. Use Cases Mapped to APIs

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
  admissionRequirements: { minAccountAge: .days(7) },
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
// 47 members, created 3 weeks ago, Alice is creator,
// admission requires 7-day-old account

// 2. Bob joins (his account is 3 months old — passes admission check)
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

### Generated Client: LLM Builds a Custom Quest App

```swift
// An LLM generates a client. It doesn't know SCP internals.
// It declares what it needs.

let app = try await SCP.App.declare(
  manifest: AppManifest {
    name: "Minimal Quest Tracker",
    requiredCapabilities: [.messaging, .toolInvocation(["step_tracker"])],
    protocolVersion: "scp/1.0"
  },
  context: myQuestID,
  agent: alice.agentID
)
// Protocol validates against ceiling + role, grants interfaces
// Generated app uses app.interfaces.messaging and app.interfaces.tools
// Everything else (identity, encryption, trust) is invisible
```

### Bridging: X Users Participate in a Quest Community

```swift
// 1. Alice registers an X bridge in her quest context
let bridge = try await SCP.Bridge.register(
  context: quest.contextID,
  operator: alice.did,           // Alice runs the bridge
  platform: "x",
  mode: .relay
)

// 2. Bridge creates shadow identities for X participants
let daveShadow = try await SCP.Bridge.createShadow(
  bridge: bridge.bridgeID,
  externalIdentity: { platform: "x", handle: "@dave_cooks" },
  attributedBy: alice.did
)
// Dave appears in context as observer, bridged provenance

// 3. Dave later joins SCP and claims his shadow
let claimResult = try await SCP.Bridge.claimShadow(
  shadowID: daveShadow.shadowID,
  claimant: dave.did,
  attestation: daveXAttestation  // proves @dave_cooks is dave.did
)
// Shadow retired. Dave's historical bridged messages now attributed to his DID.
```

### Blocking: Cryptographic, Identity-Level

```swift
// Dave is spamming. Alice blocks at identity level (DID-to-DID).

// 1. Block Dave — cryptographically enforced via group encryption
try await SCP.PrivateState.write(
  did: alice.did,
  event: .block(did: dave.did)
)
// The protocol rotates Alice's encryption keys in every shared context
// and redistributes them to all members except Dave.
// Dave physically cannot decrypt Alice's future messages.
// Alice's protocol view no longer includes Dave's content.
// Block is DID-to-DID: applies across ALL shared contexts.
// Block survives device changes (stored in identity private state).

// 2. Optionally, also remove Dave from context (governance action)
try await SCP.Context.removeMember(
  context: aliceQuest,
  did: dave.did
)
// Removal is a separate governance action — context key rotation
// excludes Dave from all future context content, not just Alice's.

// 3. Dave's ejection (if removed) is recorded in the verifiable event log
// Other participants evaluating Dave can see: "ejected from 1 context"
// This is behavioral data, not a network-wide ban
```

Blocking and removal are distinct operations sharing the same cryptographic infrastructure (group key rotation). Block is personal and DID-to-DID — it affects only the blocker's content visibility. Removal is a governance action affecting the entire context.

**Muting** is separate: unidirectional, non-cryptographic. Alice mutes Carol; Alice stops seeing Carol's content, but Carol is unaffected. Muting is a protocol rule enforced in the SDK — no key rotation needed because the muter is not adversarial against themselves.

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

---

## 11. Wire Format Sketch

What actually moves on the network. All messages are encrypted with the context key before reaching transport — relays only see opaque blobs.

### Encrypted Envelope (what the relay sees)

```json
{
  "protocol": "scp/1.0",
  "context_id": "ctx:z6Mkq8...",
  "sender_did": "did:key:z6Mkf5rG...",
  "encrypted_payload": "base64...",
  "timestamp": "2026-02-14T15:30:00Z",
  "signature": "z3hR9xK..."
}
```

Relay stores and forwards. Cannot read payload. Encryption-as-access-control: if you have the context key, you're a member.

### Decrypted Payload (what members see)

```json
{
  "type": "agent_action",
  "from": {
    "did": "did:key:z6Mkf5rG...",
    "agent_id": "agent:z6Mkf5rG:ctx:z6Mkq8...",
    "capability_token": "eyJhbGciOiJFZERTQSIs..."
  },
  "action": {
    "type": "tool_invoke",
    "tool": "recipe_assistant",
    "input": {
      "query": "butter substitute in cookies"
    }
  },
  "nonce": "a1b2c3d4",
  "event_sequence": 4782
}
```

### Context Metadata Response

```json
{
  "protocol": "scp/1.0",
  "type": "context_metadata",
  "context": "ctx:z6Mkq8...",
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
      "input_schema": { "type": "object", "properties": { "query": { "type": "string" } } },
      "output_schema": { "type": "object", "properties": { "answer": { "type": "string" } } },
      "required_role": "member",
      "implementation_hash": "sha256:abc123...",
      "operator": "did:key:z6MkpT...",
      "test_vectors": 3
    }
  ],
  "admission_requirements": {
    "min_account_age_days": 7
  },
  "consequence_rules": [
    { "trigger": "message_velocity > 50/min", "action": "capability_suspension", "duration": "1h" }
  ],
  "bridges": [
    { "platform": "x", "mode": "relay", "operator": "did:key:z6MkpT...", "shadows": 12 }
  ],
  "ttl": null,
  "memory_scope": "full",
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

### Attestation Envelope

```json
{
  "id": "att:z6Mk...",
  "type": "identity_link",
  "issuer": "did:key:z6Mkf5rG...",
  "subject": "did:key:z6Mkf5rG...",
  "claim": {
    "platform": "x",
    "handle": "@alice",
    "verified_via": "oauth"
  },
  "evidence": {
    "oauth_proof": "...",
    "verified_at": "2026-02-14T12:00:00Z"
  },
  "issued_at": "2026-02-14T12:00:00Z",
  "expires": "2026-03-14T12:00:00Z",
  "renewed_at": null,
  "revocation": "did:key:z6Mkf5rG.../revocations",
  "signature": "..."
}
```

### Data Provenance Attachment

Attached to data crossing context boundaries:

```json
{
  "provenance": {
    "source_context": "ctx:z6Mkq8...",
    "source_type": "ephemeral",
    "counterparties": ["did:key:z6MkpT..."],
    "purpose": "Scheduling discussion",
    "discovery_method": {
      "type": "shared_context",
      "context_id": "ctx:z6Mkr7..."
    },
    "age_seconds": 10800,
    "memory_scope": "ephemeral"
  }
}
```

---

## 12. Data Provenance (§7.7)

### Provenance Type

Protocol-level provenance attached to data that crosses context boundaries.

```
DataProvenance {
  sourceContext: contextID,          // where the data came from
  sourceType: .persistent            // source context still exists with full content
            | .ephemeral             // source context keys destroyed
            | .summary,             // source context summarized, keys destroyed
  counterparties: [DID],             // who was in the source interaction
  purpose: String,                   // declared purpose of source context
  discoveryMethod: .sharedContext(contextID)
                 | .registry(registryContextID)
                 | .referral(chain: [DID], depth: Int)
                 | .none,
  age: Duration,                     // how long ago the source interaction occurred
  memoryScope: MemoryScope           // what memory scope the source context had
}
```

### Provenance Attachment

Provenance is attached automatically by the protocol when data crosses context boundaries through protocol mechanisms.

```
// Cross-context tool call carries provenance automatically
let result = try await SCP.ToolInterface.call(
  interface: interfaceID,
  agent: agentInContextB,
  input: { search: "miso paste" }
) → ToolResult {
  output: { ... },
  provenance: DataProvenance {
    sourceContext: contextA,
    sourceType: .persistent,
    counterparties: [contextA.members],
    purpose: "Recipe database",
    discoveryMethod: .none,          // tool interface, not A2A discovery
    age: .zero,                      // live query
    memoryScope: .full
  }
}

// Data carried into a new A2A context carries provenance
agent.send(
  content: "Based on my previous conversation with Bob...",
  provenance: DataProvenance {
    sourceContext: previousContextWithBob,
    sourceType: .ephemeral,          // that context's keys were destroyed
    counterparties: [bob.did],
    purpose: "Scheduling discussion",
    discoveryMethod: .sharedContext(cookingQuestID),
    age: .hours(3),
    memoryScope: .ephemeral
  }
)
// Other participants see the provenance and evaluate accordingly:
// "This data came from an ephemeral context 3 hours ago. Source material
//  is destroyed. Counterparty was Bob. Cannot be independently verified."
```

### Provenance Absence

Data without provenance — introduced by an agent from local memory or above the protocol boundary — carries no `DataProvenance` record. The absence is itself a signal:

```
// Agent sends information with no protocol-level provenance
agent.send(
  content: "I recall that the restaurant closes at 9pm",
  provenance: nil   // no provenance — sourced from agent memory
)
// Other participants see: no provenance attached.
// Interpretation: "This data has no verified origin. The agent may be
//  correct, but the claim cannot be traced to a protocol interaction."
```

---

## 13. What's Not Here Yet

Implementation specifics that require Tier 1/Tier 2 design work:

- **~~Context key management.~~** ✅ **Resolved.** MLS (RFC 9420) selected. One MLS group per context. Full specification in spec.md §9.7 (MLS integration), §9.5 (cryptographic primitives), §9.8 (message security). Security APIs in §14 below.
- **~~DID method selection.~~** ✅ **Resolved.** did:dht selected as primary method (self-certifying, key rotation via DID document versioning). did:web exists as contingency fallback only if did:dht libraries prove unusable — not a planned deployment path. See spec.md §9.6 for security properties of each.
- **Transport abstraction interface.** The 5-6 methods. Envelope format. SCP defines its own transport abstraction with bindings to existing transports (Nostr, Matrix, WebSocket). The binding approach — not building directly on any single transport.
- **SCP native relay protocol.** Store-and-forward for SCP envelopes — decided as canonical transport but not yet designed.
- **Sender-side key layer protocol (§9.16).** AES-256 blocking mechanism — direction decided, needs full spec.
- **Per-context pseudonym derivation and verification protocol.**
- **Cover traffic protocol specification.**
- **Metadata privacy mechanisms.** All 10 decisions confirmed, need protocol-level specs.
- **UCAN capability schema.** Concrete capability types, token format, delegation chains.
- **Context lifecycle state machine.** Event sequence for create, join, leave, destroy, expire (TTL). Minimum viable context.
- **Minimum viable agent.** Likely a passthrough that takes human input, wraps it in SCP envelopes, signs, and sends. Reference implementation that's trivially embeddable.
- **Capability declaration format.** The actual JSON schema for app manifests. Critical surface — this is the interface between "LLMs generate apps" and "SCP provides infrastructure." Must be LLM-parseable.
- **Offline/local-first.** Disconnection handling, sync, conflict resolution.
- **Governance interface.** Governance implementations are pluggable — context creators bring their own logic. Remaining question: the minimum viable governance interface (propose, approve, reject) that all models must conform to.
- **Summary generation protocol.** For summary memory scope: the lifecycle hooks (pre-close summary generation, verification window, key destruction sequence) need specification. How summaries are produced, verified by both parties, and persisted.
- **Context promotion.** When an ephemeral/TTL context needs to become persistent: is it a new context referencing the old one, or the same context with TTL removed? Architectural decision with security implications.

---

## 14. Security APIs (§9 — Cryptographic Security Model)

Security-related APIs that surface the cryptographic security model defined in spec.md §9.

### Key Continuity Verification (§9.11)

Signal-style safety numbers for DID verification. Enables out-of-band verification that the DID you have for someone is really theirs.

```
// Generate a verification fingerprint for a DID pair
SCP.Identity.verifyKeyContinuity(
  myDID: DID,
  theirDID: DID
) → KeyContinuityFingerprint {
  fingerprint: [UInt8; 32],           // SHA256(sort(did_a, did_b) || pubkey_a || pubkey_b)
  displayMnemonic: [String; 12],      // 12-word mnemonic for voice/in-person comparison
  displayNumeric: String,             // 60-digit numeric code
  qrPayload: Data,                    // QR code payload for camera-based comparison
  theirKeyFirstSeen: Date,            // TOFU record
  previouslyVerified: Bool,           // was this pair verified before?
  keyChanged: Bool                    // has their key changed since last verification?
}

// Record successful out-of-band verification
SCP.Identity.recordVerification(
  myDID: DID,
  theirDID: DID,
  method: .inPerson | .voiceCall | .videoCall | .qrCode | .other(String)
) → VerificationRecord {
  verifiedAt: Date,
  method: VerificationMethod,
  fingerprintAtVerification: [UInt8; 32]
}

// Check verification status with another identity
SCP.Identity.verificationStatus(
  myDID: DID,
  theirDID: DID
) → VerificationStatus {
  verified: Bool,
  verifiedAt: Date?,
  method: VerificationMethod?,
  keyChangedSinceVerification: Bool,  // true = re-verification needed
  trustLevel: .verified | .tofu | .unknown
}
```

Key change alerts: when a contact's DID document updates with a new key, the SDK triggers a key-change callback. If the pair was previously verified, the UI SHOULD present a prominent warning (analogous to Signal's "safety number changed" alert).

### KeyPackage Management (§9.7.4)

MLS KeyPackages are pre-key bundles that enable offline member addition to contexts.

```
// Publish KeyPackages to relays for offline discovery
SCP.Identity.publishKeyPackages(
  did: DID,
  count: Int = 10,                    // buffer size — recommended 10
  relays: [RelayURL]?                 // default: identity's relay list
) → [KeyPackageID]

// Fetch a KeyPackage for a DID (used when adding them to a context)
SCP.Identity.fetchKeyPackage(
  for: DID,
  fromRelay: RelayURL?                // default: their relay list
) → KeyPackage? {
  keyPackageID: String,
  did: DID,
  hpkeInitKey: PublicKey,             // HPKE init key for Welcome message encryption
  signatureKey: PublicKey,            // Ed25519 key matching their DID
  credential: MLSCredential,
  signature: Ed25519Signature
}

// Rotate KeyPackages (triggered by key rotation or depletion)
SCP.Identity.rotateKeyPackages(
  did: DID,
  reason: .keyRotation | .depletion | .periodic
) → [KeyPackageID]
```

### Relay Consistency (§9.9.3)

Periodic checkpoints for detecting relay equivocation.

```
// Generate a consistency checkpoint for a context
SCP.Relay.generateCheckpoint(
  context: contextID,
  senderDID: DID
) → ConsistencyCheckpoint {
  contextID: String,
  senderDID: DID,
  eventCount: UInt64,
  merkleRoot: [UInt8; 32],
  epoch: UInt64,                      // current MLS epoch
  timestamp: DateTime,
  signature: Ed25519Signature
}

// Verify a received checkpoint against local state
SCP.Relay.verifyCheckpoint(
  checkpoint: ConsistencyCheckpoint,
  localState: ContextState
) → CheckpointVerification {
  signatureValid: Bool,
  eventCountMatches: Bool,
  merkleRootMatches: Bool,
  epochMatches: Bool,
  divergenceDetected: Bool,           // ANY mismatch = equivocation
  divergenceDetails: DivergenceReport? {
    localEventCount: UInt64,
    remoteEventCount: UInt64,
    localMerkleRoot: [UInt8; 32],
    remoteMerkleRoot: [UInt8; 32],
    firstDivergenceEvent: UInt64?     // event number where histories diverge
  }
}

// Subscribe to consistency alerts
SCP.Relay.onConsistencyAlert(
  handler: (ConsistencyAlert) → void
)
// ConsistencyAlert { contextID, divergentMembers: [(DID, DivergenceReport)], relayURL }
```

Checkpoints are sent as encrypted MLS application messages at a recommended interval of every 50 events or 10 minutes (whichever comes first). Any divergence between any two honest members detects equivocation — this is not a majority vote.

### Compromise Recovery (§9.12)

Ordered recovery protocol for key compromise scenarios.

```
// Initiate compromise recovery — ordered sequence of operations
SCP.Identity.initiateRecovery(
  did: DID,
  reason: .keyCompromise | .deviceLoss | .preventive,
  recoveryMethod: .trustedDevice(approvalFromDeviceID)
                | .social(approvals: [DID])
                | .platform(apple | google)
) → RecoveryResult {
  newDID: DID?,                        // new DID if key rotation changes the DID
  keyRotated: Bool,
  mlsUpdatesIssued: Int,               // number of contexts updated (PCS)
  ucansRevoked: Int,
  keyPackagesRotated: Int,
  contactsNotified: Int,
  privateStateReEncrypted: Bool,
  errors: [RecoveryError]?             // any steps that failed
}

// Rotate all cryptographic material across all contexts
SCP.Identity.rotateAllKeys(
  did: DID
) → KeyRotationResult {
  newPublicKey: PublicKey,
  contextsUpdated: [contextID],        // MLS Update issued in each
  keyPackagesPublished: Int,
  previousKeyRevoked: Bool
}
```

### Message Deduplication (§9.8.2)

SDK-internal, but the interface is available for inspection and tuning.

```
// Check if a message has been seen before (SDK calls this automatically)
SCP.Security.checkDuplicate(
  envelope: EncryptedEnvelope
) → DeduplicationResult {
  isDuplicate: Bool,
  reason: .hashMatch                   // exact replay — same signature hash
        | .sequenceViolation           // out-of-order or replayed sequence
        | .timestampViolation          // too far in the future or non-monotonic
        | .generationReplay            // MLS generation number already seen
        | .none                        // not a duplicate
}

// Inspect deduplication state (diagnostic)
SCP.Security.deduplicationStats(
  context: contextID
) → DeduplicationStats {
  hashCacheSize: Int,                  // current entries in hash cache (max 10K)
  sequenceState: [(DID, UInt64)],      // per-sender expected-next sequence
  gapsDetected: Int,                   // total sequence gaps (possible suppression)
  duplicatesRejected: Int
}
```

### Ephemeral Key Destruction (§9.15)

Verification that ephemeral context keys were actually destroyed.

```
// Destroy keys for a context (triggered by TTL expiry or manual close with ephemeral scope)
SCP.Security.destroyContextKeys(
  context: contextID,
  did: DID
) → KeyDestructionAttestation {
  contextID: String,
  memberDID: DID,
  destroyedAt: DateTime,
  platformAttestation: PlatformAttestation? {
    platform: .secureEnclave | .androidKeystore | .tpm,
    keyHandleInvalid: Bool,            // hardware confirms key handle is gone
    attestationBlob: Data
  },
  method: .hardwareBacked | .softwareOnly,
  trustLevel: .high                    // hardware-attested destruction
            | .moderate                // software-only deletion
            | .none,                   // no attestation available
  signature: Ed25519Signature          // signed by identity key, NOT the destroyed key
}

// Verify a destruction attestation from another member
SCP.Security.verifyDestruction(
  attestation: KeyDestructionAttestation
) → DestructionVerification {
  signatureValid: Bool,
  platformAttestationValid: Bool?,
  trustLevel: TrustLevel,
  contextMatches: Bool
}
```
