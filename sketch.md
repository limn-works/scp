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

---

## 12. What's Not Here Yet

Implementation specifics that require Tier 1/Tier 2 design work:

- **Context key management.** Group encryption protocol (MLS vs Sender Keys). Key rotation mechanics. Member add/remove key flow. **This is the first implementation domino** — it also determines the mechanics of DID-to-DID blocking (same key rotation infrastructure). MLS scales better for large contexts (O(log N) member exclusion); Sender Keys are simpler for small ones.
- **Transport abstraction interface.** The 5-6 methods. Envelope format. SCP defines its own transport abstraction with bindings to existing transports (Nostr, Matrix, WebSocket). The binding approach — not building directly on any single transport.
- **DID method selection.** `did:key` vs something with key rotation. Affects recovery.
- **UCAN capability schema.** Concrete capability types, token format, delegation chains.
- **Context lifecycle state machine.** Event sequence for create, join, leave, destroy. Minimum viable context.
- **Minimum viable agent.** Likely a passthrough that takes human input, wraps it in SCP envelopes, signs, and sends. Reference implementation that's trivially embeddable.
- **Capability declaration format.** The actual JSON schema for app manifests. Critical surface — this is the interface between "LLMs generate apps" and "SCP provides infrastructure." Must be LLM-parseable.
- **Offline/local-first.** Disconnection handling, sync, conflict resolution.
- **Governance interface.** Governance implementations are pluggable — context creators bring their own logic. Remaining question: the minimum viable governance interface (propose, approve, reject) that all models must conform to.
