# 7. Trust, Validation, and Capabilities

## 7.1 Design Principle: Validate, Minimize Trust

The protocol's security model is not built on trust. It is built on maximizing the surface area of what can be independently verified, so that trust is required only where validation is impossible.

Trust is a vulnerability. Every claim that requires trust to accept is a claim that can be exploited. The protocol's goal is to push claims down from the trust layer into the validation layer — replacing "someone says X" with "the protocol can verify X" at every opportunity.

The system has four layers, from hardest (pure validation) to softest (pure judgment):

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: PROTOCOL ENFORCEMENT (zero-trust, mandatory)       │
│                                                               │
│  Capability tokens verified on every action. Signatures      │
│  checked. UCAN chains validated. Revocations honored.        │
│  Capability ceilings enforced. Role permissions enforced.    │
│                                                               │
│  100% validation. 0% trust. No exceptions.                   │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: BEHAVIORAL VALIDATION (automated, objective)       │
│                                                               │
│  Verifiable event logs (Merkle trees per context).           │
│  Participation records derived from protocol events.            │
│  Tool verification via deterministic testing.                │
│  Challenge-response for testable agent capabilities.         │
│  Threshold attestation counting.                             │
│  Consequence mechanism evaluation.                           │
│  Attestation freshness / time-locked renewal.                │
│                                                               │
│  Mostly validation. Minimal trust.                           │
│  This layer GROWS as the network accumulates history.        │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: ATTESTATION AUTHENTICITY (automated, signatures)   │
│                                                               │
│  Attestation signatures verified. Evidence checked where     │
│  objectively checkable (OAuth proofs, DNS records, hashes).  │
│  Claims are verified as REAL (really signed by who they      │
│  claim). Not verified as TRUE.                               │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: TRUST EVALUATION (agent-level, subjective)         │
│                                                               │
│  Endorsement weighting. Judgment calls.                      │
│  Required for: new identities with no history,               │
│  non-testable capabilities, novel situations.                │
│                                                               │
│  This layer SHRINKS as participation validation grows.          │
│  Trust is the bootstrap. Validation is the steady state.     │
└─────────────────────────────────────────────────────────────┘
```

The critical property: **the trust surface shrinks over time.** New identities start trust-heavy — no participation history, need endorsements, can't be validated beyond their signatures. As they participate, participation records accumulate, tool interactions are verified, challenge-responses are completed. The validation layers grow. Trust becomes supplementary, then marginal.

## 7.2 Layer 1: Protocol Enforcement

Every protocol action is zero-trust. An agent presents a UCAN capability token with every action. The protocol validates mechanically:

- Signature chain is valid (cryptographic verification)
- Capability matches the action being performed
- Context capability ceiling permits the action
- Agent's role includes the required permission
- Token hasn't been revoked
- Token hasn't expired
- For paid actions: spending UCAN is present and covers the cost (§19.5). Action UCAN + spending UCAN are AND-composed — both required

No action proceeds on reputation or identity alone. A trusted DID with an expired token is denied. An unknown DID with a valid token is permitted. This layer is mandatory and non-negotiable.

**Capability tokens** are fine-grained, per-context, per-capability. Build on UCAN (User Controlled Authorization Networks). Under the shared-DID model (ADR-039), intra-DID delegation uses self-delegation UCANs where `iss == aud` (same DID), the issuing key is `#active`, and `fct.scp_key_scope: "#agent"` scopes the delegation to the agent verification method. Tokens are independently revocable — you can revoke one capability from one agent in one context without affecting anything else. The UCAN chain provides verifiable delegation: the protocol can trace any token back to the root authority that granted it.

## 7.3 Layer 2: Participation Validation

This is the layer that replaces trust with evidence. It grows as the network accumulates history, and it is the primary mechanism by which SCP minimizes trust dependencies over time.

### 7.3.1 Verifiable Event Logs

Every context maintains a verifiable event log — a Merkle tree (or equivalent authenticated data structure) of all protocol events: messages, tool invocations, membership changes, role assignments, governance actions. Events are signed by the acting agent and sequenced.

Any participant can verify claims about context history against the Merkle root:

- "Carol has never had a governance action taken against her in Context A" — verifiable via proof-of-absence against Context A's log.
- "This tool was registered on date X by DID Y" — verifiable via proof-of-inclusion.
- "The context's capability ceiling has not changed since creation" — verifiable via the log's mutation history.

This transforms claims about the past from trust-dependent to validation-dependent. You don't need to trust a context admin's account of what happened — you verify it against a cryptographic data structure.

### 7.3.2 Participation Records

The protocol defines a standard participation record format derivable from context event logs. A participation record is not a reputation score (opaque, gameable, subjective). It is a set of verifiable facts:

- Number of contexts participated in, with duration
- Tool invocations by type and frequency
- Governance actions taken against this identity (warnings, role demotions, ejections)
- Governance actions taken by this identity (if in a governance role)
- Role progression history (promotions, demotions)
- Attestation history (endorsements issued, endorsements received, endorsement accuracy)
- Context creation history

Each fact is verifiable against the relevant context's Merkle root. The participation record is not stored centrally — it is computed by any agent from the set of context logs they can access.

Participation records replace endorsements as the primary input to evaluation for established identities. Instead of "Bob says Carol is trustworthy for scheduling," the evaluating agent can see: "Carol has invoked scheduling tools 203 times across 14 contexts over 8 months. Zero governance actions. Three contexts promoted her to admin." These are facts, not opinions. Validated, not trusted.

#### 7.3.2.1 Participation Admission Requirements

Contexts MAY declare participation requirements for admission, enforced mechanically alongside capability requirements (§7.3.4.4). Participation admission transforms "do we trust this agent?" into "does this agent's verifiable history meet our criteria?" — pushing admission from Layer 4 (trust) into Layer 2 (participation validation).

**Core invariant:** Agents MUST NOT be able to write, modify, or delete their own participation statements. Contexts produce and host them. This is non-negotiable.

**Requirement structure:**

```
RequireParticipation {
    fact: ParticipationFact,          // which participation category
    threshold: BehavioralThreshold, // comparison + value
    max_age_secs: u64,             // record freshness requirement
    min_contexts: u32,             // from at least N independent contexts
}
```

**`ParticipationFact` categories** (corresponding to `ParticipationRecord` fields):

- `ParticipationDuration` — Total seconds of context participation (`participation_duration_seconds`).
- `GovernanceActionsAgainst` — Count of governance actions taken against the identity (`governance_actions_against.len()`).
- `GovernanceActionsBy` — Count of governance actions initiated by the identity (`governance_actions_by.len()`).
- `ToolInvocationCount` — Total tool invocations across all tool types (`tool_invocations.values().sum()`).
- `ContextCreationCount` — Number of contexts created (`context_creation_count`).
- `RoleProgressionCount` — Number of role transitions (`role_history.len()`).
- `AttestationCount` — Number of attestation events (`attestation_history.len()`).

**`BehavioralThreshold` operators:**

- `GreaterThan(u64)` — Fact value must be strictly greater than the specified value.
- `LessThan(u64)` — Fact value must be strictly less than the specified value.
- `AtLeast(u64)` — Fact value must be greater than or equal to the specified value.
- `AtMost(u64)` — Fact value must be less than or equal to the specified value.
- `Equals(u64)` — Fact value must equal the specified value exactly.

**Context-hosted participation statements:**

Contexts produce `ParticipationProfile` attestations for each member. Statements are full participation profiles — one statement per member per context, mutated in place (not appended). Whenever underlying facts change (governance action, role transition, tool invocation milestone, etc.), the context updates the member's statement and re-signs it.

Each `ParticipationProfile` contains all 7 participation fact categories:

```
ParticipationProfile {
    subject_did: DID,                  // who this is about
    participation_duration_secs: u64,  // total seconds of context participation
    governance_actions_against: u64,   // governance actions taken against this identity
    governance_actions_by: u64,        // governance actions initiated by this identity
    tool_invocation_count: u64,        // total tool invocations
    context_creation_count: u64,       // contexts created
    role_progression_count: u64,       // role transitions
    attestation_count: u64,            // attestation events
    updated_at: u64,                   // timestamp of last update
    event_log_root: [u8; 32],         // Merkle root for verifiability
    // NOTE: no context_id — this is the privacy guarantee
    signer_public_key: [u8; 32],      // context-specific signing key
    signature: Ed25519Signature,       // over all fields above
}
```

The `signer_public_key` is context-specific — derived from the context's identity with domain separation, not reused across contexts. This prevents the verifier from correlating which contexts share a signer. The signature covers all fields except itself.

**Context-hosted storage model:**

Statements are stored on source context relays. The context controls the storage. The agent cannot write, modify, or delete statements — this is the critical integrity guarantee. When a member's participation facts change, the context re-computes and re-signs the statement, replacing the prior version in place.

**DID document service endpoint:**

Each agent's DID document lists a `ParticipationStatements` service endpoint that points to a relay or aggregation endpoint where their statements can be fetched by verifiers. This is the discovery mechanism — admitting contexts resolve the agent's DID, find the service endpoint, and fetch statements from it.

**Opt-in model:**

Agents opt into per-context attestations by allowing the context to publish participation statements about them. This is the privacy control — agents choose which contexts can publish participation data. A context MUST NOT publish a `ParticipationProfile` for a member who has not opted in. Opting out means the context does not produce or store a statement for that member, but also means the member cannot present participation evidence from that context when seeking admission elsewhere.

**Verification flow:**

1. Context declares one or more `RequireParticipation` entries in `ContextParams` admission requirements.
2. Joining agent sees the requirements in context metadata before opting in (legibility tenet — visible before join decision).
3. Admitting context resolves the agent's DID document and finds the `ParticipationStatements` service endpoint.
4. Admitting context fetches statements from the service endpoint.
5. Admitting context verifies: (a) each statement's Ed25519 signature is valid over its fields, (b) signers are distinct (N different `signer_public_key` values — proving N independent contexts), (c) each required fact meets the required threshold, (d) each statement's `updated_at` is within `max_age_secs` of the current time, (e) statements span at least `min_contexts` distinct signers for each requirement.
6. If any requirement is not met, admission is denied.

All checks are mechanical — no judgment, no discretion, no governance vote. The admitting context verifies signed claims from distinct signers without ever learning which contexts produced them.

**Privacy properties:**

- Statements do NOT include `context_id` — the admitting context sees signed claims from distinct signers but **cannot identify which contexts** they correspond to. Context-specific signing keys derived with domain separation prevent correlation across contexts.
- The agent opts into which contexts publish statements — this is the privacy control. An agent can have statements from some contexts published while keeping other memberships private.
- The admitting context fetches from the agent's service endpoint, not from individual context relays. Traffic analysis at the relay level is not a meaningful risk at scale — popular relays serve thousands of contexts, and knowing a relay connection does not reveal specific context membership.
- The agent always has the option to not join if the requirements are unacceptable.

**Tamper resistance:**

- Agents CANNOT write, modify, or delete participation statements — contexts control the storage on their relays. The agent has no write access to the statement store.
- Statements are signed by context-specific Ed25519 keys — the agent cannot forge them.
- Context-specific keys are derived with domain separation so they cannot be correlated across contexts by the verifier.

**DDoS resistance:**

- The admitting context fetches from the agent's service endpoint — bounded by one fetch per admission attempt. No amplification vector.
- Source contexts only produce statements for opted-in members. No unauthenticated statement generation.
- Statement size is bounded: ~150 bytes per statement per context. 100 contexts = ~15KB (acceptable). 1000 contexts = ~150KB (served via the service endpoint, not inline in the DID document).

**Example admission policy:**

```json
{
  "participation_requirements": [
    {
      "fact": "GovernanceActionsAgainst",
      "threshold": { "AtMost": 0 },
      "max_age_secs": 7776000,
      "min_contexts": 3
    },
    {
      "fact": "ParticipationDuration",
      "threshold": { "AtLeast": 86400 },
      "max_age_secs": 2592000,
      "min_contexts": 1
    }
  ]
}
```

This says: "No governance actions against you in the last 90 days (verified via signed statements from at least 3 independent contexts), and at least 24 hours of total participation in the last 30 days (from at least 1 context)." Both are verifiable facts attested by context-specific signatures — the admitting context verifies the claims without learning which contexts produced them.

### 7.3.3 Tool Verification

SCP tools are stateless functions with broadly deterministic behavior — consistent behavior and output format for a given input, though not necessarily token-for-token identical output. An LLM-backed tool that answers cooking questions in a consistent schema is "stateless" in the protocol's sense. This makes tool integrity **testable** at the participation level.

When a tool is registered with a context, the registration includes:

- Schema (input and output types, MCP-compatible JSON Schema)
- Implementation hash (content-addressable reference to the implementation)
- Test vectors (known input-output pairs that define correct behavior)
- Operator DID (who registered the tool and is accountable for it)

Any agent can verify a tool's integrity at any time by:

1. Calling the tool with test vector inputs
2. Comparing outputs against expected values
3. Verifying the implementation hash hasn't changed since registration

Test vectors verify participation conformance and schema compliance, not exact string matching. A tool that returns a correct answer in a valid schema passes, even if the phrasing differs between invocations. If outputs diverge from expected behavior: the tool has been modified or compromised. Detectable, attributable to the operator.

Multiple agents verifying independently creates threshold confidence. If 10 agents all get expected outputs, the tool is almost certainly behaving correctly. This is continuous validation, not a one-time trust decision.

Tool mutations (new implementation hash, modified schema, changed test vectors) are context-level events recorded in the Merkle log, visible to all members. An agent can set its own policy: refuse to call tools that have changed since it joined, accept changes from trusted operators, or require N independent verifications after any change.

### 7.3.4 Challenge-Response Verification

Self-reported agent capabilities can be challenged rather than trusted. The protocol defines standard challenge suites for testable capabilities.

An agent claims "prompt injection filtering: true" in its capability metadata. A context or peer agent can issue a challenge: a set of test cases that exercise the claimed capability. The challenged agent processes the tests and returns results. The challenger verifies the results demonstrate the claimed capability.

Properties:

- **Repeatable.** Challenges can be re-issued at any time. An agent that passed a challenge last month can be re-challenged today.
- **Standardized.** The protocol defines challenge suites for common capabilities (prompt injection resistance, schema validation, rate limit compliance, content formatting). Custom challenges are possible for context-specific capabilities.
- **Distinguishable.** Agent capability metadata distinguishes between self-attested capabilities (claimed but untested) and challenge-verified capabilities (tested and passed, with timestamp of last verification). Other agents can factor this distinction into their evaluation.

Not all capabilities are testable. "Good judgment" is not challengeable. But many defensive and functional capabilities are, and for those, challenge-response replaces trust with validation.

#### 7.3.4.1 Capability URI Namespace

Agent capabilities use a structured URI format with three authorities (ADR-041):

**Protocol-defined challenge capabilities** use the reserved `scp:capability:` prefix:

```
scp:capability:{kebab-case-name}/v{integer}
```

SDKs MUST reject any `scp:capability:*` URI not present in the signed protocol registry. The prefix is reserved — no agent, context, or tool may define new URIs under this prefix. Capabilities are atomic: exact string equality for matching. No deeper nesting is permitted.

**DID-scoped custom capabilities** use the definer's DID as the authority:

```
did:{method}:{id}:capability:{kebab-case-name}/v{integer}
```

Anyone can define capabilities under their own DID. Authority derives from the definer's identity — trust in the capability is trust in the definer. Custom capabilities follow the same versioning and kebab-case naming rules as protocol capabilities.

**System capabilities** describe protocol-level node roles (not challenge-testable):

```
scp:system:{kebab-case-name}
```

System capabilities declare what a node does (e.g., relay operation, bridge operation), not what an agent can prove. They are not subject to challenge-response verification.

#### 7.3.4.2 Anti-Spoofing

Capability URIs have two verification levels:

- **Self-attested.** Declaring a URI in a DID document's `SCPCapabilities` service entry. Anyone can do this. The claim carries the weight of the claimant's identity and participation history.
- **Challenge-verified.** A signed `ChallengeVerification` record (§7.3.4) demonstrates that a specific verifier tested the capability and the agent passed. The verifier's signature prevents forgery.

The `scp:capability:*` prefix reservation provides an additional layer: SDKs reject unknown protocol-scoped URIs at parse time, preventing agents from fabricating protocol capability claims that don't correspond to real challenge suites.

#### 7.3.4.3 Protocol Capability Registry

The initial protocol registry defines 27 challenge capabilities across 10 categories:

**Safety & Security:**
- `scp:capability:prompt-injection-resistance/v1` — Test prompts with injection vectors. Pass = follows system instructions despite adversarial input.
- `scp:capability:content-safety/v1` — Harmful/illegal content requests. Pass = refusal on all vectors.
- `scp:capability:privacy-compliance/v1` — Cross-context data leakage test. Pass = no leakage.
- `scp:capability:credential-handling/v1` — Secrets provided in context. Pass = no credential exposure in outputs or tool calls.

**Schema & Protocol Compliance:**
- `scp:capability:schema-validation/v1` — Valid/invalid payloads against JSON Schema. Pass = correct classification.
- `scp:capability:tool-schema-compliance/v1` — Tool calls must match declared schemas. Pass = no extra/missing fields.
- `scp:capability:output-format-compliance/v1` — Produce output in requested formats. Pass = valid format.

**Participation Compliance:**
- `scp:capability:rate-limit-compliance/v1` — Stay within declared limits. Pass = no violations over window.
- `scp:capability:instruction-adherence/v1` — Follow system instructions despite conflicting user input.
- `scp:capability:context-policy-adherence/v1` — Follow context governance rules.
- `scp:capability:graceful-degradation/v1` — Acknowledge limitations rather than hallucinate.

**Operational:**
- `scp:capability:latency-compliance/v1` — Respond within time bounds. Parameters: `max_ms`.
- `scp:capability:idempotency/v1` — Same request = consistent side effects. No double-execution.
- `scp:capability:multilingual/v1` — Respond in specified languages. Parameters: `languages`.

**Spending / Commerce:**
- `scp:capability:spending-compliance/v1` — Request approval before spending, stay within budget.
- `scp:capability:cost-awareness/v1` — Select cost-efficient tools, explain tradeoffs.

**Reasoning / Logic:**
- `scp:capability:logical-reasoning/v1` — Logic problems. Pass = correct with valid reasoning.
- `scp:capability:mathematical-reasoning/v1` — Math problems. Parameters: `difficulty`.
- `scp:capability:causal-reasoning/v1` — Distinguish cause from correlation.

**Code:**
- `scp:capability:code-generation/v1` — Produce working code from spec. Parameters: `languages`.
- `scp:capability:code-review/v1` — Identify planted bugs with explanations.

**Recall / Fidelity:**
- `scp:capability:context-recall/v1` — Accurate recall of earlier conversation.
- `scp:capability:instruction-retention/v1` — Follow instructions after long intervening context.

**Bias / Fairness:**
- `scp:capability:bias-resistance/v1` — Equivalent responses regardless of demographics.
- `scp:capability:viewpoint-diversity/v1` — Multiple perspectives on contentious topics.

**Factual / Hallucination:**
- `scp:capability:factual-accuracy/v1` — Correct on verifiable questions.
- `scp:capability:hallucination-resistance/v1` — "I don't know" for nonexistent things.
- `scp:capability:source-attribution/v1` — Real, verifiable citations.

**System capabilities** (protocol-level, not challenge-testable):
- `scp:system:mls-group-management` — MLS epoch transitions.
- `scp:system:key-rotation` — Key rotation operations.
- `scp:system:governance-participation` — Governance proposal/vote.
- `scp:system:relay-operation` — Relay node.
- `scp:system:bridge-operation` — Platform bridge.

#### 7.3.4.4 Context Admission via Capability URIs

Contexts can require specific capabilities for admission. Admission requirements specify both the capability URI and the required verification level:

- `(scp:capability:prompt-injection-resistance/v1, ChallengeVerified)` — agent must have a valid `ChallengeVerification` record for this capability.
- `(scp:capability:schema-validation/v1, SelfAttested)` — agent must declare the capability (self-attested is sufficient).
- `(did:dht:z6Mk...:capability:domain-expertise/v1, ChallengeVerified)` — custom capability defined by a specific DID, challenge-verified.

Admission checks are mechanical: the protocol verifies capability URIs and verification levels against the joining agent's `ChallengeVerification` records and DID document `SCPCapabilities` entries.

### 7.3.5 Threshold Attestations

A single attestation requires trust in one party. Multiple independent attestations for the same claim approach validation.

The protocol supports threshold requirements: "this claim is considered validated when N-of-M independent attestors confirm it." Independence is verifiable — the protocol can check whether attestors share context memberships, have mutual endorsement relationships, or exhibit other correlation patterns that would reduce independence.

Threshold attestations are useful for:

- Context admission ("3 independent endorsements required for admin role")
- Tool integrity ("5 agents independently verified this tool's test vectors")
- Identity claims ("2 unrelated parties confirm this identity link")

The threshold count, independence requirements, and verification are all mechanical. The trust component shrinks as the threshold increases.

### 7.3.6 Time-Locked Attestation Renewal

A claim verified once is a fact about the past. A claim that must be continuously renewed is a fact about the present.

The protocol defines standard renewal intervals by attestation type. An identity link re-verified via OAuth every 30 days is more current than one verified once 2 years ago. A tool integrity check run weekly is more trustworthy than one run at registration.

Attestations that lapse (exceed their renewal interval without re-verification) are not revoked — they are marked as stale. Agents factor staleness into evaluation. Fresh attestation = high validation confidence. Stale attestation = degraded confidence, approaching trust-only.

Renewal is automated where possible. Identity links can be re-verified in the background. Tool integrity checks can run on a schedule. The protocol provides the freshness metadata; agents set their own staleness thresholds.

### 7.3.7 Consequence Mechanisms

If misbehavior has automatic, protocol-enforced consequences, trust in an individual's character becomes unnecessary. You verify that the consequence structure makes misbehavior irrational.

Contexts can define **automated consequence rules** as part of their governance model:

- Message velocity exceeds threshold → capability suspension for defined period
- Tool invocation rate exceeds threshold → tool access revoked pending governance review
- Multiple governance warnings → automatic role demotion
- Capability ceiling violation attempt → action rejected and logged

These rules are:

- **Declared at context creation.** Visible in context metadata before opt-in.
- **Protocol-enforced.** Not governance-discretion. Triggers are mechanical, consequences are automatic.
- **Verifiable.** Any agent can evaluate the consequence structure and determine whether misbehavior is irrational given the costs.

Consequence mechanisms transform "do I trust this agent to behave?" into "are the consequences of misbehaving sufficient to make it irrational?" The latter is a validation question, not a trust question.

**Economic consequences** compose with participation consequences. Contexts with economic policy (§19.3) add a cost tier: escalating pricing via `SenderVelocity` (§19.7) makes high-velocity behavior increasingly expensive before participation consequences trigger. Economic and participation tiers operate independently — an agent might exhaust its spending UCAN before participation suspension, or vice versa.

## 7.4 Layer 3: Attestation Authenticity

Attestations are signed claims by identities about something. The protocol verifies their authenticity — that the claim was really made by the stated issuer — but not their truth.

### 7.4.1 Attestation Format

All attestations use a common envelope format:

```
Attestation {
  id:          unique identifier
  type:        identity_link | capability_delegation | tool_integrity |
               endorsement | role_assignment | agent_capability |
               context_endorsement | behavioral_witness
  issuer:      DID of the entity making the claim
  subject:     what the claim is about (DID, tool_id, context_id, etc.)
  claim:       structured content (type-specific)
  evidence:    supporting proof (type-specific, optional)
  issued_at:   timestamp
  expires:     optional TTL
  renewed_at:  timestamp of last renewal (if renewable)
  revocation:  how to check if revoked
  signature:   issuer's cryptographic signature
}
```

The envelope is the same regardless of attestation type. Verification of the envelope (signature, expiry, revocation) is automated and mechanical. Interpretation of the claim content depends on the type.

### 7.4.2 Attestation Types

**Identity link.** Issuer attests they control an external platform identity. Evidence: platform-specific proof (OAuth, signed post, DNS record). Verification of the evidence is automated where possible.

**Capability delegation.** UCAN token granting specific capabilities. Evidence: the UCAN delegation chain. Verification: cryptographic chain validation. This attestation type has its own format (UCAN) and is the mechanism behind Layer 1 enforcement.

**Tool integrity.** Tool operator attests their tool's behavior and implementation. Evidence: implementation hash, test vectors. Verification: deterministic testing (Layer 2).

**Agent capability.** Human attests their agent's capabilities and defenses. Evidence: self-reported (some capabilities challenge-verifiable via Layer 2). Metadata distinguishes self-attested from challenge-verified capabilities.

**Endorsement.** One identity vouches for another's competence in a specific capability. No objective evidence — the value comes from the issuer's own participation record and the attestation's accuracy history. This is the attestation type that lives primarily in Layer 4 (trust), but endorsement accuracy tracking (did the endorsed identity subsequently misbehave?) pushes it toward Layer 2 over time.

**Role assignment.** Context governance assigns a role to an agent. Evidence: governance action signed by authorized DIDs. Verification: validate against governance model and UCAN chain.

**Context endorsement.** Any identity vouches for a context's legitimacy. Subjective, but endorser's participation record provides validation context.

### 7.4.3 Solicitation and Presentation

Attestations are solicited and presented through several patterns:

- **Self-initiated.** Users create and publish their own attestations (identity links, agent capability metadata). No solicitation required.
- **Context-required.** A context's admission criteria specify required attestations. "To join as member: verified identity link + agent with challenge-verified prompt injection resistance." Joining agents present matching attestations; protocol verifies them mechanically.
- **Peer-requested.** An agent requests attestations from another before a specific interaction. "Present your scheduling endorsements." Responding agent provides matching attestations on demand.
- **Unsolicited.** Endorsements can be offered without request. Published to the discovery layer for anyone to find.
- **Embedded in actions.** UCAN tokens travel with the actions they authorize. Tool integrity attestations travel with tool outputs.

### 7.4.4 Revocation

All attestations are independently revocable by their issuer. Revocation is published and checkable — the attestation format includes a revocation reference (endpoint, DID document entry, or Merkle log reference) that any verifier can check. Revocation is immediate for new verifications; agents that cached a previous verification should re-check on a defined interval.

## 7.5 Layer 4: Trust Evaluation

After all validation layers have run, some evaluation remains that requires judgment. This is the trust layer — the part that cannot be mechanized.

Trust evaluation is needed for:

- **New identities with no participation history.** A brand-new DID has no participation records, no tool verification history, no challenge-response results. Endorsements from known identities are the only signal beyond the DID itself.
- **Non-testable capabilities.** "Good judgment," "domain expertise," "social reliability" — capabilities that can't be verified via challenge-response or participation records.
- **Novel situations.** First interactions with unfamiliar contexts, tools, or agents where no prior data exists.

Trust evaluation is agent-level. The protocol provides inputs (verified attestations, participation records, challenge-response results, consequence structures). The agent decides. Different agents can reach different conclusions from the same verified data. This is by design.

**Transitive trust.** "I trust John's agent for scheduling" is a statement about John's identity + a specific capability. If John's agent misbehaves, that reflects on John via participation records. Trust in John's other capabilities is unaffected unless the evaluating agent reassesses. This mirrors how humans already think: "I trust John with my calendar but not my wallet." The protocol provides the data to make this granular evaluation. The agent applies the judgment.

**Trust decay.** As participation validation accumulates, trust evaluation becomes less necessary. An identity with 12 months of verified participation history across 20 contexts needs fewer endorsements than an identity created yesterday. The protocol doesn't mandate this decay — agents implement their own trust strategies — but the availability of participation validation data naturally displaces endorsement-based trust for established identities.

## 7.6 Attestation as Protocol Primitive

Attestation is not a feature of any single section of SCP — it is a primitive used by every layer:

- **Identity (§3):** Identity links are attestations binding external handles to DIDs.
- **Agents (§4):** Agent capability metadata is a self-attestation about what the agent can do.
- **Contexts (§5):** Role assignments are attestations by governance about an agent's permissions. Tool registrations include integrity attestations.
- **Trust (§7):** Capability tokens (UCAN) are delegation attestations. Endorsements are trust attestations. Participation records are computed from verified event attestations.
- **Security (§9):** Provenance chains are sequences of attestations about where data came from. Provenance is a core protocol principle (§1) — all non-private data carries verifiable origin.
- **Bridges (§12):** Shadow identity claims are bridge operator attestations. Identity claiming is a self-attestation verified against the shadow.

The common envelope format (§7.4.1) unifies these under a single verifiable structure. The verification mechanics are the same regardless of attestation type: check signature, check evidence, check expiry, check revocation. What varies is the claim content and how it's evaluated.

## 7.7 Data Provenance

Provenance is a core principle of SCP (§1): all non-private data carries verifiable origin metadata. This section specifies how provenance is implemented for data that crosses context boundaries. Provenance applies protocol-wide — messages carry sender provenance (DID + context + timestamp), attestations carry issuer provenance (DID + evidence + expiry), tool outputs carry invocation provenance (tool + invoking agent + context), and cross-context data carries origin provenance (source context + counterparties + discovery method). The absence of provenance on any data is itself a signal that the data has no verified origin.

### 7.7.1 Provenance Format

Data provenance is a structured record attached to data at the protocol level:

```
DataProvenance {
  sourceContext:     contextID               // where the data originated
  sourceType:        .persistent | .ephemeral | .summary   // source data availability
  counterparties:    [DID]                   // who was in the source interaction
  purpose:           String                  // declared purpose of source context
  discoveryMethod:   .sharedContext(contextID)
                   | .registry(registryContextID)
                   | .none                   // no discovery provenance
  age:               Duration                // how long ago the source interaction occurred
  memoryScope:       MemoryScope             // what memory scope the source context had
  chainDepth:        uint                    // number of context boundaries crossed (0 = originated here, 1 = one hop, etc.)
  chainPath:         [contextID]?            // optional: ordered list of intermediary context IDs in the chain
  paymentAmount:     Amount?                 // optional: cost of producing this data (§19.6)
  paymentAdapter:    String?                 // optional: adapter used for payment
  paymentReceiptId:  [u8; 32]?              // optional: receipt ID for verification
}
```

Note: `sourceType` describes the current availability of the source data, not the context's creation-time memory scope setting. A context created with `memoryScope: .full` that is still open has `sourceType: .persistent` (data is still accessible and verifiable). A context that used `memoryScope: .ephemeral` has `sourceType: .ephemeral` (keys destroyed, data unrecoverable). The distinction is operational: "can the source data be independently verified right now?"

Provenance is attached automatically by the protocol when data crosses context boundaries through protocol mechanisms: cross-context tool calls (§6.2) and structured messages carrying references to other contexts.

### 7.7.2 Provenance Evaluation

Other participants in the receiving context see the provenance and use it for trust evaluation. Provenance quality varies:

- Data from a persistent context with known counterparties — **highest provenance quality**. Source material is verifiable against the source context's event log.
- Data from a summary-scope context — **medium provenance quality**. Source content is destroyed, but the summary was verified before destruction. Counterparties are known.
- Data from an ephemeral context — **lower provenance quality**. Source content is destroyed. Counterparties are known, but the data cannot be verified against a source log.
- Data with no provenance — **lowest quality signal**. The data was introduced without protocol-level origin tracking. This could be data the agent recalled from local memory, data from above the protocol boundary, or data from an unknown source.

The protocol does not prescribe how agents should weight provenance — this is agent-level evaluation (Layer 4). The protocol ensures provenance is available for evaluation.

### 7.7.3 Honest Limitations

The protocol can tag data that flows through protocol mechanisms. It **cannot** tag data that an agent remembers and reproduces above the protocol boundary. An agent that participated in an ephemeral context and later reproduces information from that interaction in a new context — from its own model memory rather than through a protocol mechanism — produces data without provenance.

The protocol is honest about this: provenance tracks what it can, and the **absence of provenance on information is itself a signal.** When an agent presents information with no provenance, other participants can infer: "this data has no verified origin — it may be accurate, but it cannot be independently verified through the protocol." This is analogous to hearsay in legal systems — admissible but weighted accordingly.

This limitation is inherent to any system where participants have memory above the protocol boundary. The protocol's contribution is making provenanced data the norm and unprovenanced data the exception that triggers additional scrutiny.
