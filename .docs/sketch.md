# SCP API Design Sketch

**Status:** Working sketch — interfaces, not implementation
**Purpose:** Make the protocol tangible through concrete API surfaces and use cases
**Aligned with:** .docs/specs/ (working draft, February 2026), planning-session-06.md (resolved decisions)

---

## 1. Identity

### Create Identity

First launch. User never sees keys. Device attestation proves real device.

```
SCP.Identity.create(
  custody: .secureEnclave | .passkey | .platform(apple|google) | .selfManaged,
  recovery: [.trustedDevice, .socialRecovery, .platformBacked],
  deviceAttestation: DeviceAttestation     // Apple App Attest / Google Play Integrity
) → Identity {
  did,
  identityKey,          // Ed25519 — derives the DID string, highest-security custody (ADR-003)
  activeSigningKey,     // Ed25519 — MLS credentials, envelope signatures, UCAN issuance (rotatable)
  preRotationCommitment, // SHA-256(pre-rotation key public) — cold/offline custody
  custodyMethod
}
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

Contexts are bounded, encrypted, governed spaces — cryptographic entities (one MLS group each) where all protocol-level interaction happens. They are runtime objects (~5-15ms local, ~200ms wall clock to create), not infrastructure to deploy. They survive process restarts. Long-lived contexts are where apps live; ephemeral contexts are where bounded tasks happen.

### Create (template-based — primary path, §5.12)

```
// Template-based creation — the fast path for common patterns.
// Templates are protocol constants with fixed, predictable configurations.
SCP.Context.create(
  creator: Identity,
  template: .bilateralEphemeral     // messages only, ephemeral, TTL required
          | .bilateralPersistent    // messages only, full memory, no TTL
          | .coordination           // messages + tools, summary memory, TTL required
          | .groupDiscussion        // messages + invite, full memory, optional TTL
          | .publicBroadcast        // broadcast mode, auto-granted subscriber reads, optional TTL
          | .gatedBroadcast,        // broadcast mode, admin-issued subscriber reads, optional TTL
  peer: DID?,                       // for bilateral templates — handles invitation internally
  ttl: Duration?,                   // required for some templates, optional for others
  tools: [ToolDefinition]?          // only for templates that allow tools (coordination)
) → Context { contextID, creatorDID, templateID, ceiling, roles, governance, ttl?, memoryScope }
```

For bilateral templates, the SDK bundles context metadata + MLS Welcome message into a single transport delivery. The peer receives everything needed to evaluate and join in one message. With auto-accept (§5.12.2), the join is fully autonomous — no human delay.

### Create (explicit params — advanced path)

```
// For contexts that don't fit a well-known template.
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

### Create Child (context nesting, §5.13)

```
// Single-parent child: sub-space within a context
SCP.Context.createChild(
  creator: Identity,
  parents: [contextID],            // one or more parent contexts
  ceiling: [Capability],           // must be ≤ intersection of parent ceilings
  governance: GovernanceModel,
  roles: { ... },
  ttl: Duration?,                  // must be ≤ minimum parent TTL (if parents have TTLs)
  memoryScope: MemoryScope,
  tools: [ToolDefinition]?,
  parentGovernanceConfig: {        // per parent — what authority each parent retains
    [contextID]: ParentGovernanceConfig {
      canCloseChild: Bool,
      canEvictMembers: Bool,
      canRestrictCeiling: Bool,
      requiresApprovalFor: [.governanceChange | .toolRegistration | .ceilingChange | .membershipChange],
      onSever: .evictUniqueMembers | .cascadeClose | .preserveMembership
    }
  }
) → Context { contextID, parents, ceiling, roles, governance, parentGovernanceConfig }
```

For multi-parent children, governance approval from every parent is required. The creator needs creation rights in at least one parent; additional parents approve independently via their own governance. Parent context IDs and governance config hash are bound into the child's MLS `group_context` extensions — lineage is cryptographically unforgeable.

Members must be in at least one parent to join the child. Eligibility is continuous: lose your last parent, lose the child.

### Standing Channel (contact graph, §5.12.6)

```
// Get-or-create a bilateral-persistent context with a peer.
// Idempotent: returns existing if one exists.
SCP.Context.standingChannel(
  identity: Identity,
  peer: DID
) → Context { contextID, peer, template: .bilateralPersistent }
```

Standing channels are bilateral-persistent contexts used for ongoing direct communication. Zero idle cost (no keepalives, ~2-5KB storage each). Persist across restarts. The agent's contact graph.

### Auto-Accept Policies (§5.12.2)

```
// Configure local auto-accept policy. Evaluated entirely in the SDK, never shared.
SCP.Context.setAutoAcceptPolicy(
  identity: Identity,
  policy: AutoAcceptPolicy {
    template: TemplateID,            // which template(s) to auto-accept
    from: .sharedContext             // DID shares ≥1 active context with me
        | .knownDID([DID])           // explicit allowlist
        | .discoveryContext,         // DID registered in trusted context
    maxTTL: Duration?,               // optional cap
    rateLimit: Rate?                 // max auto-accepts per time window
  }
) → void
```

**Hard rule (non-overridable):** Auto-accept never applies to contexts with tool capabilities in the ceiling. Tool access always requires explicit confirmation.

### Inspect (before opt-in)

Anyone can read this. This is the "what am I walking into" view.

```
SCP.Context.inspect(
  contextID
) → ContextMetadata {
  contextID,
  templateID: TemplateID?,         // if created from a well-known template (§5.12)
  ceiling: [Capability],
  roles: { name: [Capability] },
  governance: GovernanceModel,
  admissionRequirements: AdmissionRequirements?,
  consequenceRules: [ConsequenceRule]?,
  creator: DID,
  memberCount: Int,
  age: Date,
  ttl: Duration?,                  // time-to-live if set (§5.10)
  memoryScope: MemoryScope,        // ephemeral, summary, or full (§5.11)
  tools: [ToolMetadata],          // name, description, input/output schema
  toolInterfaceCount: { inbound: Int, outbound: Int },  // active cross-context interfaces (§6.2)
  bridges: [BridgeInfo]?,         // active bridge connectors, if any
  // For child contexts (§5.13):
  parents: [{
    contextID: contextID,
    ceiling: [Capability],
    governance: GovernanceModel,
    memberCount: Int,
    age: Date,
    governanceConfig: ParentGovernanceConfig   // what authority this parent has
  }]?,
  eligibilityBasis: [contextID]?   // which parent(s) the inspecting DID would join through
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

### Add Member

Governance action. Requires admin role or governance approval. The invitee's KeyPackage is fetched from the relay and used for MLS Welcome message construction.

```
SCP.Context.addMember(
  context: contextID,
  identity: DID,                     // DID of the member to add
  role: String,                      // role to assign (must exist in context's role map)
  as: Identity,                      // must have admin role or governance authority
  attestations: [Attestation]?       // optional attestations on behalf of the invitee
) → MembershipResult {
  contextID: ContextId,
  memberDID: DID,
  role: String,
  capabilityTokens: [UCANToken],     // UCAN tokens scoped to this context and role
  eventID: EventID                   // MemberJoined event in the event log
}
```

Admission requirements are checked mechanically against the invitee's profile. The MLS Welcome message is delivered to the invitee via the relay. The invitee's SDK processes the Welcome to join the MLS group. A `MemberJoined` event is appended to the context's event log.

### Remove Member

Governance action. Requires admin role or governance approval.

```
SCP.Context.removeMember(
  context: contextID,
  target: DID,
  as: Identity,                    // must have admin role or governance authority
  reason: String?                  // recorded in event log
) → void
```

Removal triggers MLS group key rotation — the removed member loses cryptographic access to all future content. Distinct from blocking (which is personal, DID-to-DID, sender-key-based).

### List

```
SCP.Context.list(
  for: Identity,
  filter: .all | .created | .member | .observer
) → [ContextSummary]
```

### Receive (streaming)

Stream incoming messages and events from a context. The stream stays open as long as the membership is active.

```
SCP.Context.receive(
  context: contextID,
  as: Identity,
  filter: .all | .messages | .events | .toolResults
) → AsyncStream<ContextEvent> {
  message: Message?,
  event: ProtocolEvent?,
  toolResult: ToolResult?
}
```

The stream primitive provides real-time delivery of all context activity. Transport-level details (reconnection, backoff, multi-relay fanout) are handled by the SDK. The stream respects the participant's role — events outside their capability ceiling are filtered.

**Buffer semantics:** The receive stream buffers up to 1,000 events. When the buffer is full, the oldest unconsumed event is dropped and a `BufferOverflow` warning event is emitted on the stream. SDKs MAY expose buffer size as a configuration parameter (minimum: 100, maximum: 10,000, default: 1,000). The `BufferOverflow` event includes the count of dropped events since the last successful consumption, enabling consumers to detect and respond to backpressure.

### Broadcast Context: Create (§5.14)

Broadcast contexts use per-author AES-256 keys instead of MLS. No group key management — authors manage their own broadcast keys.

```
SCP.Context.createBroadcast(
  template: "public-broadcast" | "gated-broadcast",
  name: String,
  as: Identity,
  params: {
    description: String?,
    projectionPolicy: ProjectionPolicy?,   // HTTP projection settings (§18.11)
    ttl: Duration?
  }
) → Context { contextID, mode: .broadcast, role: "author" }
```

### Broadcast Context: Subscribe (§5.14.3)

Subscribers register via DID-signed requests. Open broadcasts grant access on registration; gated broadcasts require a `messagesRead` UCAN from the context admin.

```
SCP.Broadcast.subscribe(
  context: contextID,
  as: Identity,
  wrappingPubkey: X25519PublicKey,          // for HPKE-sealed key delivery
  ucan: UcanToken?                          // required for gated contexts
) → Subscription {
  contextID,
  role: "subscriber",
  authors: [{ did: DID, keyEpoch: u64 }]   // current author key epochs
}
```

### Broadcast Context: Request Author Key (§5.14.2, §5.14.3)

Pull-based key distribution. Subscriber requests a specific author's broadcast key for a given epoch. Author SDK checks block list (and UCAN for gated contexts) before responding.

```
SCP.Broadcast.requestKey(
  context: contextID,
  authorDid: DID,
  epoch: u64,
  as: Identity
) → BroadcastKey {
  authorDid: DID,
  epoch: u64,
  key: AES256Key                            // HPKE-sealed with subscriber's wrapping pubkey
}
```

### Broadcast Context: Publish (§5.14.5)

Authors publish messages as `BroadcastEnvelope`s — signed and encrypted with the author's current broadcast key.

```
SCP.Broadcast.publish(
  context: contextID,
  content: Data,
  as: Identity,
  provenance: DataProvenance?
) → BroadcastReceipt {
  sequence: u64,
  keyEpoch: u64,
  contentHash: [u8; 32],
  timestamp: u64
}
```

Send path: validate UCAN (`messagesWrite`) -> assign sequence -> generate nonce -> hash plaintext -> sign (Ed25519 over `context_id || sender_did || sequence || key_epoch || timestamp || nonce || content_hash || provenance_hash`) -> AES-256-GCM encrypt with author broadcast key -> wrap in OuterEnvelope -> relay PUBLISH.

### Broadcast Context: Receive (§5.14.5)

```
SCP.Broadcast.receive(
  context: contextID,
  as: Identity,
  filter: .all | .byAuthor(DID)
) → AsyncStream<BroadcastMessage> {
  senderDid: DID,
  sequence: u64,
  keyEpoch: u64,
  content: Data,
  provenance: DataProvenance?,
  timestamp: u64,
  verified: Bool                            // signature + AEAD tag both valid
}
```

Receive path: transport receive -> dedup by blob hash -> deserialize -> verify Ed25519 signature -> decrypt with cached author broadcast key -> verify content_hash -> verify author UCAN -> replay check (sequence number) -> deliver.

### Broadcast Context: Rotate Key / Block (§5.14.2, §5.14.8)

On block, the author increments their key epoch and generates a new broadcast key. Blocked subscribers cannot request the new key.

```
SCP.Broadcast.block(
  context: contextID,
  targetDid: DID,
  as: Identity                              // must be the author
) → BlockResult {
  newKeyEpoch: u64                          // epoch advanced automatically on block
}

SCP.Broadcast.unblock(
  context: contextID,
  targetDid: DID,
  as: Identity
) → void
// Unblocked subscriber can request the current key on next pull
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

### Update

Update a tool's registration (schema, description, test vectors, implementation hash). Records the change in the context event log.

```
SCP.Tool.update(
  context: contextID,
  agent: agentID,
  tool: "recipe_assistant",
  changes: {
    description: String?,
    input: JSONSchema?,
    output: JSONSchema?,
    testVectors: [TestVector]?,
    implementationHash: ContentHash?
  }
) → ToolUpdateResult {
  previousHash: ContentHash,
  newHash: ContentHash,
  eventID: EventID
}
```

Only the tool's operator (or context admin) can update. Schema changes that break existing test vectors are rejected. The event log records both the old and new implementation hashes for auditability.

### Cross-Context Tool Interface (§6.2)

Both contexts opt in. Calls carry provenance including chain depth. Schema constraints enforce structural specificity (no unbounded string-only interfaces, minimum two distinct fields). Chain depth limit (default: 8, context-configurable via `ContextParams::max_chain_depth`, ADR-043) prevents amplification.

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
) → ToolResult {
  output,
  provenance: DataProvenance {
    sourceContext: contextA,
    chainDepth: 1,                 // one context boundary crossed
    chainPath: [contextA],
    ...
  }
}

// Stateful sessions (§6.2.1) — optional multi-turn interactions
SCP.ToolInterface.call(
  interface: interfaceID,
  agent: agentInContextB,
  sessionID: "sched:abc123"?,      // continue existing session (opaque to caller)
  input: { action: "propose", times: ["Tue 3pm"] }
) → ToolResult {
  output: { sessionID: "sched:abc123", status: "pending" },
  provenance: DataProvenance { ... }
}
// Per-caller session cap (default: 1000, context-configurable via ContextParams::session_cap, ADR-043) prevents exhaustion. Optional session TTL.
```

### Revoke Tool Interface

Either side can revoke a cross-context tool interface. Revocation is a governance action — it requires admin role or governance approval in the revoking context. Active sessions on the interface are terminated. Revocation is recorded in the event logs of both contexts.

```
SCP.ToolInterface.revoke(
  interface: InterfaceID,
  as: Identity,                      // must have admin role or governance authority
  reason: String?                    // recorded in event log
) → ToolInterfaceRevocationResult {
  interfaceID: InterfaceID,
  revokedBy: DID,
  revokedAt: Timestamp,
  terminatedSessions: Int,           // count of active sessions terminated
  eventID: EventID                   // InterfaceRevoked event in the event log
}
```

Revocation is permanent for the given `InterfaceID`. To re-establish the interface, a new `SCP.ToolInterface.expose()` call is required, producing a new `InterfaceID`. Both contexts must opt in again.

**Two cross-context mechanisms** (§6.1). Tool interfaces are asymmetric (caller/tool). Multi-parent child contexts (§5.13) are symmetric — a shared space where members from different parent contexts interact as peers. Use tool interfaces for service calls; use multi-parent children for collaboration.

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

The three-method interface (propose, approve, reject) is the mandatory protocol contract. All governance models must implement it. Single-admin auto-approves; multi-sig waits for threshold; consensus waits for all members. Custom governance models are pluggable within this interface.

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
) → Result<ShadowClaimEvent, ClaimError>
// On success: shadow retired, history attributed to claimant DID
// On error: ClaimError (HandleMismatch, AttestationInvalid, AlreadyClaimed, ShadowNotFound)
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

### Use Case: Creating a Collaborative Context with Tools

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

// 2. The app's AI guide agent joins with "guide" role
try await SCP.Context.addMember(
  context: quest.contextID,
  identity: guideAgent,          // App operator's institutional DID
  role: "guide"
)

// 3. Alice's agent invokes the guide
let advice = try await alice.agent.invoke(
  tool: "guide_assistant",
  input: { query: "where do I start with Thai cooking?" }
)
```

### Use Case: Joining a Public Context

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

## 11. Real-Time Media (§10.9.1)

Media sessions use the delegated transport model: SCP governs identity, trust, and signaling; WebRTC handles media transport. The context's capability ceiling must include the relevant `media.*` capability.

### Initiate Media Session

```
SCP.Media.initiate(
  context: contextID,
  as: Identity,
  capabilities: [.voice] | [.voice, .video] | [.screenShare],
  participants: [DID]?   // nil = all context members
) → MediaSession {
  sessionID: string,
  mediaKeys: MediaKeyMaterial,  // MLS-exported keying material
  signalingChannel: contextID   // signaling flows through the context
}
```

The SDK exports keying material from the MLS group's key schedule (RFC 9420 §8, MLS exporter) bound to the session ID. This key material is used to derive DTLS-SRTP keys for media encryption. Only current MLS group members can derive the keys — membership enforcement is cryptographic.

### Exchange Signaling

WebRTC signaling (SDP offers/answers, ICE candidates) flows as standard SCP messages within the context. This means signaling is end-to-end encrypted and authenticated.

```
SCP.Media.signal(
  session: sessionID,
  context: contextID,
  as: Identity,
  payload: SDPOffer | SDPAnswer | ICECandidate
)
```

### Export Media Keys

Derives DTLS-SRTP key material from the MLS group state, bound to the session.

```
SCP.Media.exportKeys(
  session: sessionID,
  context: contextID,
  as: Identity
) → MediaKeyMaterial {
  dtlsFingerprint: bytes,
  srtpMasterKey: bytes,
  srtpMasterSalt: bytes
}
```

Key material is re-exported on MLS epoch advances. If a member is removed from the context (and thus from the MLS group), they lose the ability to derive current media keys — the media session enforces the same membership as the context.

### End Media Session

```
SCP.Media.end(
  session: sessionID,
  context: contextID,
  as: Identity
)
```

Termination is signaled through the context. Participants tear down WebRTC connections. Session end is recorded in the event log.

---

## 12. Wire Format Sketch

What actually moves on the network. All messages are encrypted with the context key before reaching transport — relays only see opaque blobs.

### Outer Envelope (what the relay sees)

```json
{
  "protocol": "scp/1.0",
  "routing_id": "z4K9xR...",
  "recipient_hint": "z7Lm3Q...",
  "ttl": 604800,
  "blob": "base64..."
}
```

The outer envelope is minimal by design (spec §9.10.2). The relay sees only:
- **routing_id** — per-context pseudonym derived via HMAC-SHA256 (spec §9.10.4). Unlinkable across contexts.
- **recipient_hint** — recipient's per-context pseudonym for directed messages, or `"*"` for broadcast.
- **ttl** — seconds until the relay should delete this blob.
- **blob** — the encrypted payload. Everything else is inside.

No sender DID. No context ID. No timestamp. No signature. The relay is a dumb pipe.

### Decrypted Payload (what members see after MLS + sender-key decryption)

```json
{
  "type": "agent_action",
  "context_id": "ctx:z6Mkq8...",
  "from": {
    "did": "did:dht:z6Mkf5rG...",
    "pseudonym": "z4K9xR...",
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
  "epoch": 42,
  "generation": 7,
  "sequence": 4782,
  "timestamp": "2026-02-14T15:30:00Z",
  "signature": "z3hR9xK...",
  "nonce": "a1b2c3d4"
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
    "admin": "did:dht:z6MkpT..."
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
      "operator": "did:dht:z6MkpT...",
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
    { "platform": "x", "mode": "relay", "operator": "did:dht:z6MkpT...", "shadows": 12 }
  ],
  "ttl": null,
  "memory_scope": "full",
  "template_id": null,
  "tool_interface_count": { "inbound": 3, "outbound": 1 },
  "parents": null,
  "members": 47,
  "created": "2026-01-20T10:00:00Z",
  "creator": "did:dht:z6MkpT..."
}
```

### Capability Token (UCAN-shaped)

```json
{
  "header": { "alg": "EdDSA", "typ": "JWT", "ucv": "0.10.0" },
  "payload": {
    "iss": "did:dht:z6MkpT...",
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
  "issuer": "did:dht:z6Mkf5rG...",
  "subject": "did:dht:z6Mkf5rG...",
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
  "revocation": "did:dht:z6Mkf5rG.../revocations",
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
    "counterparties": ["did:dht:z6MkpT..."],
    "purpose": "Scheduling discussion",
    "discovery_method": {
      "type": "shared_context",
      "context_id": "ctx:z6Mkr7..."
    },
    "age_seconds": 10800,
    "memory_scope": "ephemeral",
    "chain_depth": 1,
    "chain_path": ["ctx:z6Mkr7..."]
  }
}
```

---

## 13. Data Provenance (§7.7)

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
                 | .outOfBand,
  age: Duration,                     // how long ago the source interaction occurred
  memoryScope: MemoryScope,          // what memory scope the source context had
  chainDepth: uint,                  // number of context boundaries crossed (0 = originated here)
  chainPath: [contextID]?            // optional: ordered list of intermediary context IDs
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
    discoveryMethod: .outOfBand,     // tool interface discovery
    age: .zero,                      // live query
    memoryScope: .full
  }
}

// Data carried into a new context carries provenance
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

## 14. Discovery (§6.2.2)

### Unified Discovery

The SDK provides a single entry point that searches local contacts and all known contexts with discovery tools.

```
SCP.Discovery.search(
  query: DiscoveryQuery {
    capability: String?,           // e.g., "translation"
    keywords: [String]?,           // free-text search terms
    minHistory: Int?               // minimum context participation count
  }
) → [DiscoveryResult] {
  did: DID,
  capabilities: [String],          // from DID document + registry metadata
  behavioralSummary: BehavioralSummary?,
  source: .localContact            // cached DID document
        | .discoveryContext(contextID),
  provenance: DataProvenance        // where the result came from
}
```

### Registration

Agents register in contexts with discovery tools via DID-authenticated requests to tool endpoints. Registration does not require MLS group membership — registrants are readers, not writers (see spec §6.2.2 two-tier model).

```
// Register in a context with discovery tools (reader-tier, DID-authenticated)
SCP.Discovery.register(
  context: contextID,              // the context to register in
  identity: Identity,
  capabilities: [String],
  metadata: {
    description: String?,
    tags: [String]?
  }
) → RegistrationResult { registered: Bool, entryID: String }

// Remove registration (reader-tier, DID-authenticated)
SCP.Discovery.deregister(
  context: contextID,
  identity: Identity
) → void

// Update DID document capabilities (published via did:dht)
SCP.Discovery.publishCapabilities(
  identity: Identity,
  capabilities: [String],
  version: String = "scp/1.0"
) → void
```

### Bootstrap

```
// Query default contexts with discovery tools on first identity creation (reader-tier)
SCP.Discovery.bootstrap(
  identity: Identity,
  autoRegister: Bool = true        // opt-out via config
) → [contextID]                    // contexts with discovery tools connected to

// Add a custom context
SCP.Discovery.addContext(
  contextID: contextID
) → void
```

---

## 15. What's Not Here Yet

Implementation specifics that require Tier 1/Tier 2 design work:

- **~~Context key management.~~** ✅ **Resolved.** MLS (RFC 9420) selected. One MLS group per context. Full specification in .docs/specs/ §9.7 (MLS integration), §9.5 (cryptographic primitives), §9.8 (message security). Security APIs in §16 below.
- **~~DID method selection.~~** ✅ **Resolved.** did:dht selected as primary method (self-certifying, key rotation via DID document versioning). did:web exists as contingency fallback only if did:dht libraries prove unusable — not a planned deployment path. See .docs/specs/ §9.6 for security properties of each.
- **~~Transport abstraction interface.~~** ✅ **Resolved.** ADR-005 specifies the `TransportAdapter` trait (send, subscribe, unsubscribe, query, delete). Envelope format specified in .docs/specs/ §9.10.2 (minimal outer envelope).
- **~~SCP native relay protocol.~~** ✅ **Resolved.** ADR-004 specifies the relay: PUBLISH/SUBSCRIBE/UNSUBSCRIBE over WebSocket, blob TTL enforcement, recipient_hint for directed delivery.
- **~~Sender-side key layer protocol (§9.16).~~** ✅ **Resolved.** Full specification in .docs/specs/ §9.16 (5 subsections). ADR-007 specifies implementation. AES-256-GCM sender keys, HPKE-wrapped per-recipient distribution using stable wrapping keypairs, block protocol, forward secrecy interaction.
- **~~Per-context pseudonym derivation and verification protocol.~~** ✅ **Resolved.** Specified in .docs/specs/ §9.10.4. HMAC-SHA256 derivation, inside-encryption verification, caching.
- **~~Cover traffic protocol specification.~~** ✅ **Resolved.** Specified in .docs/specs/ §9.10.6. Configurable, default on for persistent connections.
- **~~Metadata privacy mechanisms.~~** ✅ **Resolved.** All 10 decisions implemented. Full architecture in .docs/specs/ §9.10 (8 subsections).
- **~~UCAN capability schema.~~** ✅ **Resolved.** ADR-016 specifies concrete capability types, 11-step validation pipeline, delegation chains, nonce replay rejection, ceiling enforcement.
- **~~Context lifecycle state machine.~~** ✅ **Resolved.** ADR-008 specifies states (Creating, Active, Closing, Closed, Expired), transitions, TTL management, governance enforcement.
- **~~Context templates and lightweight creation.~~** ✅ **Resolved.** .docs/specs/ §5.12 specifies 6 well-known templates (4 encrypted + 2 broadcast), auto-accept policies, invitation bundling, computational profile, standing bilateral contexts. sdk-common.md specifies cross-language SDK surface.
- **~~Context nesting.~~** ✅ **Resolved.** .docs/specs/ §5.13 specifies parent-child relationships (8 subsections): ceiling inheritance, membership eligibility, creation protocol, parent governance configuration, lifecycle coupling, metadata/legibility, interaction with other mechanisms, depth limits. Cryptographic binding via MLS `group_context` extensions. ADR-008 defines the `ChildContextCreate` capability. Nesting implementation (`nesting.rs`) is deferred to a later phase (see SCP-134 in the PRD).
- **~~Cross-context provenance chain tracking.~~** ✅ **Resolved.** DataProvenance type includes `chainDepth` (boundary hop count) and `chainPath` (intermediary context IDs). Chain depth limit (default: 8, context-configurable, no protocol hard max per ADR-043) enforced at context level. .docs/specs/ §7.7.1.
- **~~Minimum viable agent.~~** ✅ **Resolved.** MCP server/client translating between model and SCP SDK. See `00-open-questions.md`, §4.4–4.5, §8.5. Tracked at [#364](https://github.com/limn-works/scp/issues/364).
- **~~Capability declaration format.~~** ✅ **Resolved.** JSON Schema (MCP-compatible) with SCP-specific extensions. §8.4 specifies the contract; §8.5 establishes MCP compatibility. See `00-open-questions.md`.
- **~~Offline/local-first.~~** ✅ **Resolved.** ADR-029 specifies offline/sync strategy. §23 specifies the full sync protocol. Three-tier recovery (local replay, peer sync, governance-triggered reset).
- **~~Governance interface.~~** ✅ **Resolved.** ADR-031 specifies multi-admin governance. `GovernanceEngine` trait with `SingleAdmin`, `Threshold`, `Majority`, and `Unanimity` models. 30 governance action types. §5.9 specifies the governance proposal lifecycle.
- **~~Summary generation protocol.~~** ✅ **Resolved.** §5.11 specifies memory scope enforcement including summary lifecycle: pre-close generation, 300-second verification window, key destruction. Summary format defined by context tools/governance.
- **~~Context promotion.~~** ✅ **Resolved.** §5.10 specifies `PromotionPolicy` (declared at creation, immutable). Same context with TTL removed. Requires unanimous consent. `PromoteContext` governance action in ADR-031.

---

## 16. Security APIs (§9 — Cryptographic Security Model)

Security-related APIs that surface the cryptographic security model defined in .docs/specs/ §9.

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

---

## 17. Economy

### Cost Estimation (§19.4, §19.11)

Evaluate a context's pricing formula against current observable metrics.

```
SCP.Economy.estimateCost(
  context: ContextID,
  action: PaidActionType           // .message | .toolInvoke | .join | .period | .byteStored
) → CostEstimate {
  amount: Amount,
  currency: CurrencyCode,
  formulaInputs: {                 // observable metrics used in computation (all integer — §19.1.1)
    contextMessageRate: Int?,      // messages in current window
    memberCount: Int?,
    senderVelocity: Int?,          // sender's messages in sliding window
    storageUsage: Int?,            // bytes
    timeOfDay: Int?                // UTC hour (0-23)
  },
  breakdown: {
    baseCost: Amount,
    variableComponents: [(PricingVariable, Amount)],  // each variable's contribution
    cap: Amount?,
    floor: Amount?
  }
}
```

### Payment History (§19.6, §19.11)

Retrieve payment receipts from a context's event log.

```
SCP.Economy.paymentHistory(
  context: ContextID,
  filter: PaymentFilter? {
    payer: DID?,
    payee: DID?,
    actionType: PaidActionType?,
    since: DateTime?,
    limit: Int?                    // default: 50
  }
) → [PaymentReceipt {
  receiptId: [u8; 32],
  payer: DID,
  payee: DID,
  amount: Amount,
  currency: CurrencyCode,
  actionType: PaidActionType,
  contextId: ContextID?,
  adapterId: String,
  adapterProof: Data,             // x402: tx hash, Lightning: preimage, SPL: tx sig
  timestamp: DateTime,
  signature: Ed25519Signature     // signed by payer
}]
```

### Grant Spending UCAN (§19.5, §19.11)

Mint a spending capability UCAN for an agent.

```
SCP.Identity.grantSpending(
  agent: DID,
  context: ContextID?,              // None = wildcard "scp:spending:*", Some = "scp:spending:{contextId}"
  capability: SpendingCapability {
    maxPerAction: Amount,          // max single-action spend
    maxTotal: Amount,              // max total spend within timeWindow
    currency: CurrencyCode,        // ISO 4217 or protocol-defined
    timeWindow: Duration,          // rolling window for maxTotal
    allowedAdapters: [String]      // empty = any configured adapter
  },
  expiry: DateTime                 // MUST NOT exceed 24 hours (§9.5)
) → UcanToken {
  encoded: String,                 // JWT-encoded UCAN
  resource: "scp:spending:{contextId}" | "scp:spending:*",
  capability: SpendingCapability,
  chain: [DID]                     // delegation chain (human → agent)
}
```

Spending UCANs are AND-composed with action UCANs. Agent needs both `messagesWrite` + spending UCAN to send paid messages. Attenuation: sub-delegation must narrow (agent granted $100/day can delegate $10/day to sub-agent).

### Configure Payment Adapter (§19.2.4, §19.11)

Register a payment adapter with the identity's SDK instance.

```
SCP.Identity.configureAdapter(
  adapter: PaymentAdapter {
    adapterId: String,             // "x402" | "lightning" | "spl" | "stripe" | custom
    capabilities: AdapterCapabilities {
      supportedCurrencies: [CurrencyCode],
      supportsStreaming: Bool,
      supportsBatchAuth: Bool,
      supportsSingleStep: Bool,
      minAmount: Amount?,
      maxAmount: Amount?,
      typicalSettlementMs: Int,
      requiresFacilitator: Bool
    }
  }
) → ()
```

Adapter credentials are identity-private state (§3.7) — encrypted, stored alongside identity keys. Never exposed to contexts or relays.

### Context Creation with Economic Policy (§19.3, §19.11)

Extended context creation with optional economic policy.

```
SCP.Context.create(
  template: TemplateID?,
  params: ContextParams {
    // ... existing params (ceiling, governance, mode, ttl, memoryScope) ...
    economicPolicy: EconomicPolicy? {
      locked: Bool,                // true = immutable, false = governed (default)
      costSchedule: CostSchedule {
        currency: CurrencyCode,
        perMessage: Amount?,
        perToolInvoke: Amount?,    // default for tools without own cost
        perJoin: Amount?,          // one-time membership cost
        perPeriod: SubscriptionCost?,
        perByteStored: Amount?
      },
      paymentAdapters: [PaymentAdapterRef],
      pricingFormula: PricingFormula?,
      payee: DID
    }
  }
) → Context
```

Auto-accept (§5.12.2) NEVER applies to contexts with economic policy requiring payment.

### Context Inspection with Economic Policy (§19.9, §19.11)

Extended context inspection surfaces economic metadata.

```
SCP.Context.inspect(
  context: ContextID
) → ContextMetadata {
  // ... existing metadata (ceiling, governance, roles, members, mode, ttl) ...
  economicPolicy: EconomicPolicy?,  // pricing, adapters, payee — visible before opt-in
  estimatedCostPerMessage: Amount?,  // convenience: pre-computed from current formula
  estimatedCostPerToolInvoke: Amount?
}
```
