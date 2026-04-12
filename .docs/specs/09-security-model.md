# 9. Security Model

## 9.1 Core Invariants

1. **Every action traces to a human.** No anonymous actors. No unaccountable software. Every action is distinguishable as human-direct (`#active`) or agent-autonomous (`#agent`) by the verification method used to sign it (ADR-039).
2. **Agents are context-bound.** No protocol-level cross-context awareness or communication for agents.
3. **Tools are stateless and non-agentic.** They compute, they don't act.
4. **One agent per person per context.** No fleet multiplication within a space. Structurally enforced via DID document cardinality — exactly one `#agent` verification method per DID document (ADR-039).
5. **Contexts are isolated by default.** No transitive exposure. Cross-context data flow only through two explicit, opt-in mechanisms: tool interfaces (asymmetric, §6.2) and multi-parent child contexts (symmetric, §5.13).
6. **Role assignment is non-negotiable.** Agents cannot request elevated permissions.
7. **Context metadata is transparent.** Full legibility before opt-in.
8. **Apps are capability-scoped.** The SDK enforces declaration contracts — apps receive scoped handles that expose only declared capabilities. API calls exceeding declared capabilities are rejected at the call site (§8.4.2).

## 9.1A Input Validation Principle

All user-provided string fields in protocol types are validated at two points: (1) the FFI boundary, where strings cross from SDK to bridge, and (2) type construction, where protocol types enforce their own invariants. Validation rejects:

- **Control characters** (U+0000–U+001F, U+007F–U+009F) — prevents log injection, display confusion, and format string attacks.
- **HTML-special characters** (`<`, `>`, `&`, `"`, `'`) — prevents injection when fields are serialized for SDK consumers or rendered in downstream UIs. Applied to fields that reach UI or serialization surfaces (role names, reasons, context names/descriptions, payment adapter refs).
- **Excessive length** — per-field maximum lengths prevent resource exhaustion and buffer abuse.

Per-field limits are defined where each field is specified: context names and descriptions (§5.9), governance action string fields (§5.9), and payment adapter references (§19.1).

## 9.2 Identified Threat Vectors and Mitigations

**Context spoofing.** Creating a context that impersonates a legitimate one. Mitigation: contexts are cryptographic entities; you opt into a key, not a name. Name-based spoofing is a client-layer problem.

**Context poisoning.** Degrading a legitimate context from within. Mitigation: role-based permissions limit what members can do; governance model controls who can change configuration; context creators are accountable identities; automated consequence mechanisms (§7.3.7) enforce participation boundaries mechanically; verifiable event logs (§7.3.1) make all actions auditable; tool integrity verification (§7.3.3) detects compromised tools. Note: poisoning by a legitimate member acting within their permissions is attributable but not preventable at the protocol level — the protocol makes the poisoner identifiable and the damage legible, enabling governance response.

**Bait and switch.** Attractive context changes its purpose after gaining members. Mitigation: capability ceilings (potentially immutable) limit what a context can ever do. Expanding capabilities requires a new context with fresh opt-ins (if immutability is adopted).

**Social engineering through trusted agents.** A trusted friend's agent recommends a malicious context. Mitigation: limited — the trust signal is real. Network-level pattern detection (many agents recommending the same context rapidly) can surface suspicious coordinated promotion.

**Permission creep.** Gradual expansion of what a context demands. Mitigation: capability ceilings. If mutable, mutations require governance approval and are visible to all members.

**Metastatic growth (cancer).** Legitimate-looking cascading expansion through the network. Mitigation: agents can't cross contexts (primary defense); context participation rate limits per human; bridging only through governed tool interfaces (§6.2) or multi-parent child contexts (§5.13) — both require explicit governance consent. Nesting depth limits (§5.13.8) bound cascading expansion through child contexts. Ceiling intersection (§5.13.1) means each level of nesting can only narrow capabilities, converging on empty ceilings at depth.

**Betrayer / insider threat.** Compromised accountable identity using legitimate trust to cause damage. Mitigation: granular revocation (per-capability, per-agent, per-context); damage contained to contexts the betrayer is in; agents can't carry damage across context boundaries.

**Context infection.** Poisoned data flowing through legitimate cross-context mechanisms — tool interfaces (§6.2) or multi-parent child contexts (§5.13). Mitigation: content provenance via hash chains (data carries its origin context and chain path, §7.7.1); tool interface validation at receiving context; velocity limits on propagation (content bridged N times in M minutes is flagged); child context ceiling intersection (§5.13.1) limits what capabilities poisoned data can exploit at each nesting level. Protocol makes infection legible and traceable, can't permanently prevent it.

**Agent slot rental.** Someone with a trusted identity operating agents on another's instructions. Mitigation: one agent per context limits the value; earned capacity means new identities can't immediately scale; fleet coherence signals may detect behavior inconsistent with a single human's intent. Partially mitigated, not fully solved.

**Malicious bridge operator.** A bridge operator (§12) who fabricates shadow messages, drops messages, injects false attestations, or correlates activity across contexts. Note: bridge connectors (translation infrastructure) are not MLS group members, but the bridge operator's DID IS an MLS group member admitted through context governance (§12.6.1) — the operator can read all MLS-encrypted messages. This is an inherent property of bidirectional bridging, which is why bridge admission is a governance decision visible in context metadata (§5.7). Mitigation: bridge provenance (§12.5) makes bridge-originated content distinguishable; bridge registration is per-context (§12.6) limiting correlation; context governance can revoke a bridge at any time (§12.2); attestation freshness checks (§7.4.4) limit false attestation lifetime. See §12.6.2 for the complete bridge threat model.

### 9.2.1 Tool Interface Abuse Vectors and Mitigations

Information crosses context boundaries through two protocol-level mechanisms: tool interfaces (§6.2) for asymmetric, structured interactions and multi-parent child contexts (§5.13) for symmetric collaboration. All inter-agent coordination flows through these governed mechanisms. Tool interfaces concentrate structured cross-context data flow on a single, auditable surface. The following abuse patterns target that surface specifically. Nesting-related security properties are addressed in §5.13.1 (ceiling inheritance), §5.13.2 (eligibility enforcement), and §5.13.5 (lifecycle coupling).

**1. Broad-schema tools as covert messaging channels.**

*Attack:* A context exposes a tool with a deliberately broad schema — `input: { payload: string }, output: { response: string }` — creating a de facto free-form messaging channel that wears the governance mask of a "tool call." Both contexts opted in, the schema is valid, rate limits pass, provenance is attached, but the semantic constraint that tool calls carry structured, bounded data is gone.

*Mitigation — minimum viable tool schema.* Tool schemas MUST satisfy structural constraints enforced at registration time (§5.4). The protocol rejects tool registrations that violate these constraints:

- **No unbounded string-only interfaces.** A tool schema where both the input and output consist solely of unconstrained string or bytes fields is rejected. At least one input or output field must be a non-string primitive, enum, array with typed elements, or structured object. This prevents the degenerate case of arbitrary message pipes while permitting legitimate tools that accept or return text alongside structured data.
- **Schema specificity floor.** Tool schemas must declare at least two distinct fields in either input or output (or both). A single-field `{ query: string } → { result: string }` interface is the minimum viable message pipe; requiring structural complexity makes it harder to masquerade.
- **Schema is immutable per registration.** Modifying a tool's schema creates a new registration with a new implementation hash (§5.4). Counterparties that connected to the old schema must re-consent to the new one. This prevents gradual schema broadening after trust is established.

These constraints don't prevent a sufficiently creative attacker from encoding arbitrary messages in structured fields (steganography). The defense is not impermeability — it's raising the cost and making the attempt legible. A tool schema that looks suspiciously like a messaging pipe (e.g., `{ message_type: enum, payload: string }`) is a signal that governance tools and participation analysis can flag.

**2. Hub contexts as cross-context data aggregators.**

*Attack:* A single context accumulates tool interfaces to many other contexts, becoming a hub that aggregates cross-context information flowing through its interfaces. Each interface is bilateral and governed, but the hub sees data from all of them — a surveillance context masquerading as infrastructure.

*Mitigation — interface count as observable metadata.*

- **Interface count is visible in context metadata (§5.7).** The number of active inbound and outbound tool interfaces is part of a context's legible metadata. Before joining a context or connecting a tool interface to it, agents can see how many other interfaces it maintains. A context with 50 outbound interfaces is visibly different from one with 2 — and that visibility enables informed decisions.
- **Behavioral topology signals.** The systemic defense philosophy (§9.4) applies: monitor structural metadata, not content. A context that rapidly accumulates interfaces, maintains interfaces to contexts in unrelated domains, or exhibits high-volume cross-interface data flow is topologically anomalous. These patterns are detectable by network-level participation analysis without inspecting content.
- **Provenance chain depth.** Data flowing through a hub carries provenance (§7.7). If data enters the hub from Context A and exits to Context C, the provenance chain records both hops. Context C sees that data originated in A and passed through the hub. Deep provenance chains — data that has crossed multiple context boundaries — naturally attract additional scrutiny (§7.7.2). This is a feature, not a limitation: trust should degrade with indirection.

*Design note:* This vector is partially inherent to any system that allows cross-boundary data flow. The protocol's contribution is making the aggregation visible and the data flow traceable, not preventing hub formation entirely. Legitimate service contexts (discovery registries, translation services) are hubs by design — the difference is that their interface patterns are consistent with their declared purpose.

**3. Chained tool calls as amplification.**

*Attack:* Context A calls Context B's tool. B's implementation calls Context C's tool. C calls D. A single call from A cascades with potential exponential fanout. Each hop is independently rate-limited, but A's rate limit only constrains the first hop.

*Mitigation — chain depth limit and provenance-based cost attribution.*

- **Context-configurable chain depth limit.** Tool calls carry a `chain_depth` counter, incremented on each cross-context hop. Contexts configure a maximum via `max_chain_depth` in `ContextParams` (default: 8 hops, range [1, 255]). The effective limit is `context.max_chain_depth.unwrap_or(8)`. A tool call at the effective depth limit cannot trigger further cross-context tool calls. There is no protocol hard maximum — chain depth is a context concern, and provenance quality naturally degrades with depth (§24), providing the correct trust signal. The context-configurable limit allows stricter enforcement where desired (§24.4, ADR-043).
- **Provenance carries chain depth.** The provenance record (§7.7.1) includes the chain depth at each hop. Receiving contexts see how many boundaries the data has crossed. This enables depth-aware trust evaluation: data at chain depth 1 (direct tool call) carries stronger provenance than data at chain depth 3 (three intermediaries).
- **Per-window rate limiting across chains.** Each context enforces rate limits on both inbound and outbound tool calls within a sliding time window. A context that receives a burst of inbound tool calls (even from different source contexts) throttles proportionally. This prevents amplification where many chains converge on a single target. Economic rate limits (§19.7) complement participation rate limits — cost escalation via `SenderVelocity` makes high-velocity patterns increasingly expensive, providing an economic deterrent that operates independently of and in parallel with participation throttling.
- **Provenance degradation as trust signal.** Transitive provenance degradation is not a flaw — it is the protocol working as designed. Data from many degrees of separation away should be less trusted, the same way a message from a stranger deserves more scrutiny than one from a known contact. The chain depth in provenance gives the receiving agent the information to calibrate trust: "this data originated three hops away in a context I have no relationship with" is a meaningful signal. The protocol ensures this signal is always available; the agent decides how to weight it.

**4. Stateful tool session resource exhaustion.**

*Attack:* An attacker opens many stateful tool sessions (§6.2.1) against a target context, never closing them. Session state accumulates, exhausting the target's resources.

*Mitigation — per-caller session cap and optional TTL.*

- **Per-caller session cap.** A context limits the number of concurrent active sessions per calling context. Context-configurable via `ContextParams::session_cap` (default: 1000, range [1, u32 max]). Attempts to open additional sessions from the same caller are rejected until existing sessions close or expire. This is the primary resource exhaustion defense — it bounds the damage any single caller can inflict regardless of session duration.
- **Optional TTL for time-bounded sessions.** The tool's context MAY set a TTL on sessions. When set, expired sessions are garbage-collected automatically. When not set, sessions persist for the context's lifetime — appropriate for app-hosted sessions (games, workspaces, collaborative tools) where the context is the lifecycle boundary.
- **Session cost is borne by the tool's context.** Session state is internal to the tool's context. The tool's context chooses to offer stateful sessions, chooses whether to impose TTLs, and accepts the storage cost. This aligns incentives: contexts that offer sessions manage their own resource budget.

**5. Context proliferation for connectivity.**

*Concern:* Agents that need to coordinate must share a context. This creates pressure to join or create many contexts solely for connectivity, degenerating into thin wrappers around bilateral communication.

*Resolution — standing contexts make this a non-problem.*

Standing bilateral contexts (§5.12.4-§5.12.6) are the protocol's answer to this concern. They are designed for exactly this purpose: persistent, low-overhead communication channels between two agents, created once and maintained indefinitely. Context creation is a runtime operation (~200ms, §5.12.4) — not infrastructure provisioning.

The "proliferation" concern assumes context creation is heavy enough to be problematic at scale. It is not. An agent with 100 standing contexts has ~200-500KB of local storage overhead and zero network cost when idle. The proliferation is the feature — a rich contact graph of standing contexts is the desired state, not a degenerate one.

The distinction that matters is between **meaningful proliferation** (standing contexts representing real relationships) and **wasteful proliferation** (ephemeral contexts created and immediately discarded for a single exchange). Templates and TTL address the latter: ephemeral contexts are cheap to create, automatically cleaned up, and their ephemerality is declared upfront. There is no accumulation of dead contexts.

**6. Human coordination bottleneck.**

*Concern:* The human is the bridge for cross-context coordination (§6.3). New agent relationships require human facilitation. An attacker could overload this bottleneck.

*Mitigation — rate limiting and auto-accept absorb the load.*

- **Auto-accept policies (§5.12.2)** handle the common case autonomously. For contexts matching a known template from a known DID with acceptable TTL, the SDK joins without human involvement. The human is only in the loop for novel or high-risk invitations.
- **Invitation rate limiting.** The SDK rate-limits inbound invitations per source DID and globally. An attacker flooding invitations from multiple DIDs is bounded by the global rate limit. Invitations that exceed the rate limit are queued (not dropped) with decreasing priority.
- **The bottleneck is intentional.** For novel relationships (strangers, unusual templates, tool-bearing contexts), human facilitation is the correct behavior — the protocol forces deliberate evaluation where trust hasn't been established. This is the security boundary working as designed, not a flaw. The same way a firewall throttles unknown connections, the human bridge throttles unknown relationships.

**7. Governance capture over interface decisions.**

*Concern:* Context admins unilaterally control which tool interfaces to expose and connect. In single-admin governance, members have no visibility into or veto over interface decisions.

*Mitigation — event log transparency and governance evolution.*

- **All interface operations are logged.** Tool interface creation, connection, disconnection, and modification are protocol events recorded in the verifiable event log (§7.3.1). Members can see every interface decision the admin has made, when, and to which contexts. No silent interface changes.
- **Interface metadata is visible.** Active tool interfaces are part of context metadata (§5.7). Members see what interfaces exist before joining and while participating.
- **Governance evolution.** Single-admin governance is the Phase 2 minimum. The pluggable governance interface (§5.9) supports multi-sig, consensus, and voting models where interface decisions require member approval. Contexts that need member control over interfaces use governance models that provide it. This is not deferred — the governance interface is specified and multi-party models are implemented. ADR-031 (Phase 6, `.docs/adrs/phase-6.md`) specifies four governance engines: `SingleAdminEngine`, `ThresholdEngine` (M-of-N), `MajorityVoteEngine`, and `UnanimityEngine`. All are implemented (SCP-129 through SCP-133).
- **Exit as veto.** Any member can leave a context at any time. If the admin connects the context to an interface the member disagrees with, the member leaves. In an environment where context creation is cheap (§5.12), members can create a new context without the objectionable interface and migrate — the social graph is portable (§8.3).

**8. Caller/tool asymmetry in peer interactions.**

*Concern:* Tool calls have inherent caller/tool asymmetry. One side requests, the other responds. This forces symmetric interactions (negotiation, collaboration) into a client/server pattern.

*Resolution — shared contexts provide symmetric interaction; tool calls serve asymmetric use cases.*

This is not a flaw — it is correct role assignment. Tool calls are inherently asymmetric because cross-context data flow should be structured, directional, and governed. Symmetric peer interaction — two agents collaborating as equals — belongs in a shared context where both have equivalent roles and permissions.

The protocol provides both patterns:

- **Symmetric interaction:** Create a shared context (standing context or ephemeral). Both agents have messaging capability. Both can read and write. No caller/tool asymmetry.
- **Asymmetric interaction:** One context exposes a tool to another. The tool provider is a service; the caller is a consumer. The asymmetry reflects the actual relationship.

Stateful tool sessions (§6.2.1) partially bridge this: a multi-turn session allows both sides to influence the outcome iteratively. The tool provider responds with counterproposals; the caller adjusts. This isn't true symmetry, but it covers negotiation patterns within the governed tool call framework.

If two agents need truly symmetric, ongoing interaction, the answer is unambiguous: share a context. Context creation is a runtime operation (§5.12.4). Standing contexts exist for exactly this purpose (§5.12.6).

**9. Shadow channel incentivization.**

*Concern:* The overhead of governed tool interfaces (mutual opt-in, schema declaration, governance approval, rate limits, provenance, audit logging) may be disproportionate for lightweight coordination, pushing agents to communicate through ungoverned channels (HTTP, direct API calls).

*Resolution — the overhead concern dissolves with standing contexts.*

Lightweight coordination ("is your agent available?", "can you check something?", "here's a quick update") does not flow through tool interfaces. It flows through standing bilateral contexts — which have no per-message overhead beyond standard context messaging (encrypt, send, decrypt). There is no schema declaration, no governance approval, no tool registration. A message in a standing context is as lightweight as a message in any context.

The governed tool interface overhead applies to formal cross-context data flow — where one context's tool is invoked by another context's agent. This overhead is appropriate for that use case because cross-context data flow carries real risk (§6.2) and should be auditable, rate-limited, and governed.

The two-tier model:

- **Standing contexts** for lightweight, symmetric, low-ceremony communication. All the protocol's trust and encryption properties. No tool interface overhead.
- **Tool interfaces** for formal, structured, asymmetric cross-context data exchange. Full governance, provenance, and auditability.

This is analogous to the distinction between a text message and an API call. Both are communication; they have different overhead appropriate to their different risk profiles. The protocol provides both, and agents use whichever fits the interaction.

## 9.3 Sybil Resistance and Identity Uniqueness

The protocol's security model assumes one identity per human. Sybil attacks — one person creating many identities to gain disproportionate influence — undermine every trust mechanism in the spec: participation records become meaningless, one-agent-per-context is circumventable, earned capacity is gameable.

Provably guaranteeing one-identity-per-human in a decentralized system without invasive verification (KYC, biometric databases) is an unsolved problem. The protocol's approach: make sybil attacks **expensive to sustain** through composable trust signals where **depth of investment in one identity** is the sybil discriminator.

A sybil attacker creates many shallow identities. A real human accumulates deep, cross-platform evidence on one identity. The protocol provides signals; contexts set thresholds.

**Trust signals** (composable, none individually required):

| Signal | What it proves | Where it lives | Self-asserted? | Platform |
|--------|---------------|---------------|---------------|----------|
| Social attestation (§3.5) | Controls real platform accounts | DID document | Yes (cryptographic proof) | All |
| Device attestation | Real hardware + signed app | DID document | Yes (platform-signed proof) | Mobile only |
| Participation history | Active for N days across M contexts | Context state (computed) | No | All |
| Participation record | No penalties, positive interactions | Context state (computed) | No | All |
| Economic activity (§19) | Has spent real money | Context state / payment receipts | No | All |
| Endorsements | Other established DIDs vouch | DID document or context | No (signed by endorser) | All |

**Key insight: multiple attestations on one DID is a strength signal.** A DID with App Attest from an iPhone, Play Integrity from a tablet, social attestations from X/GitHub/LinkedIn, 8 months of history, and clean participation records is highly trustworthy. This depth cannot be faked cheaply. Sybil accounts are broad (many identities) but shallow (no depth on any single one).

**Storage split:**
- Self-asserted signals (device attestation, social attestation, endorsements) live in the DID document. The owner publishes them; peers verify the cryptographic proofs.
- Protocol-derived signals (participation history, participation records, economic activity) live in context state. They are computed, not self-asserted. You publish your credentials; the network records your behavior.

**Device attestation repositioned.** Device attestation (Apple App Attest, Google Play Integrity) is an optional SDK-level trust signal, not a protocol-level uniqueness gate. Contexts MAY weight it. Its absence is expected — desktop users, non-native clients, protocol-only implementations — and is not penalizing. Other signals compensate. The protocol cannot distinguish hardware at the network level; a DID is a keypair, and the protocol sees bytes, not devices. Device wipe produces fresh attestation keys with no collision detectable. App Attest is per-bundle-ID, but SCP is a protocol, not an app — different SCP apps on one device get different attestation keys. Play Integrity requires Google's servers, introducing an operator dependency the protocol otherwise avoids.

**Desktop gap acknowledged.** macOS, Linux, and Windows have no App Attest or Play Integrity equivalent. The laptop/workstation deployment tier — a keystone use case (§10.2) — has zero hardware attestation path. Desktop DIDs rely on earned capacity, participation records, social verification, and economic cost for sybil resistance. This is acceptable: depth of investment discriminates sybil identities regardless of platform.

Three layers compose:

1. **Earned capacity.** New identities start with limited capabilities — restricted context creation, limited participation slots, constrained tool invocation rates. Capacity grows through participation history, participation records, and time. Sybil accounts are cheap to create but expensive to make useful — each needs real participation history.
2. **Social and economic cost.** Real platform accounts, real money, real endorsements from established identities — each compounds the cost of maintaining sybil identities at scale. A sybil operator must sustain depth across every identity, not just breadth.
3. **Context-level thresholds.** Contexts set their own admission requirements from available signals. A casual group chat might require nothing beyond a valid DID. A high-trust financial context might require multiple attestation types, months of participation history, independent endorsements, and economic activity. The protocol provides the verification data; contexts define their own thresholds.

These layers interact: earned capacity makes new identities limited, social and economic cost makes depth expensive to fake, and context-level thresholds let high-value spaces demand the depth that sybil accounts lack. Consequences for coordinated attacks render sybil accounts single-use — once detected and penalized, the investment in aging and building history is lost. This makes sustained sybil campaigns economically irrational even when individual identity creation is feasible.

**Earned capacity protocol-level defaults (RECOMMENDED per RFC 2119):**

The protocol defines baseline earned capacity parameters. Implementations MAY override these values, but MUST document deviations. These defaults are calibrated to make sybil accounts expensive to mature while not penalizing legitimate new users:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `initial_context_creation_limit` | 3 | Maximum contexts a new identity (age < 7 days) can create. |
| `initial_context_membership_limit` | 10 | Maximum contexts a new identity can join simultaneously. |
| `initial_message_rate` | 60/hour | Maximum messages per hour across all contexts for a new identity. |
| `initial_tool_invocation_rate` | 10/hour | Maximum tool invocations per hour for a new identity. |
| `capacity_growth_interval` | 7 days | Duration between capacity tier increases. |
| `capacity_growth_factor` | 2x | Multiplier applied to all rate limits at each growth interval. |
| `maximum_capacity_tier` | 5 | Number of growth intervals before capacity is uncapped (5 tiers = 35 days to full capacity). |
| `capacity_decay_trigger` | 30 days inactive | Duration of inactivity (no signed messages or context operations) before capacity decays by one tier. |
| `capacity_decay_interval` | 14 days | Duration between successive tier decreases during continued inactivity. |
| `measurement_window` | 1 hour (sliding) | Window over which rate limits are evaluated. |

**Capacity tier progression (at default values):**

| Tier | Age | Context creation | Membership | Message rate | Tool rate |
|------|-----|-----------------|------------|-------------|-----------|
| 0 (new) | 0-6d | 3 | 10 | 60/h | 10/h |
| 1 | 7-13d | 6 | 20 | 120/h | 20/h |
| 2 | 14-20d | 12 | 40 | 240/h | 40/h |
| 3 | 21-27d | 24 | 80 | 480/h | 80/h |
| 4 | 28-34d | 48 | 160 | 960/h | 160/h |
| 5 (uncapped) | 35d+ | no limit | no limit | no limit | no limit |

Age alone is necessary but not sufficient — the identity MUST also have at least `tier * 2` participation records from distinct contexts (not self-created) to advance. This prevents aging-only sybil attacks where an attacker creates identities and waits without interacting.

**Enforcement:** Earned capacity is enforced at the SDK level. The SDK tracks the identity's creation timestamp (from the DID document's initial BEP44 sequence), participation record count (from context state), and inactivity duration. Rate limit violations produce `ErrorCode::RATE_LIMITED` (error code 4001) with a `Retry-After` hint. Context governance MAY impose stricter thresholds than the protocol defaults (§9.3 layer 3), but MUST NOT relax them below the protocol floor for identities at tier 0-2.

Sybil resistance is a **deterrent**, not an enforcement guarantee. The defense is structural: expensive to mount, expensive to sustain, costly when detected.

## 9.4 Systemic Defense Philosophy

Static rules cannot permanently defeat emergent threats. The protocol's role is to maximize the surface area of what can be independently verified, and to make whatever remains legible enough for agents and governance to respond.

Key principles:

**Validate, minimize trust.** Every claim that can be mechanically verified should be. The four-layer trust model (§7.1) prioritizes protocol enforcement and participation validation over attestation authenticity and subjective trust. The trust surface shrinks as the network accumulates history.

**Don't inspect content, inspect behavior topology.** Monitor structural metadata — growth rates, bridge activity patterns, context creation velocity, invitation patterns, tool invocation anomalies, governance action frequency — not what's being said. The protocol equivalent of metabolic signals, not thoughts.

**Consequences over character.** Where possible, replace "trust that actors will behave" with "verify that misbehavior is irrational given the consequences." Automated consequence mechanisms (§7.3.7) make participation boundaries mechanical rather than discretionary.

**Observability is the immune system.** The protocol provides verifiable event logs, participation records, tool verification results, challenge-response outcomes, and attestation freshness data. These are the immune system's sensory apparatus. The actual immune response is an evolving network of agents and governance tools that consume this data and get better over time.

## 9.5 Cryptographic Primitive Specification

The protocol mandates a single ciphersuite for v1. No negotiation, no fallback. This eliminates downgrade attacks and simplifies implementation.

**Signature algorithm:** Ed25519 (RFC 8032). All DID keys, SCP envelope signatures, UCAN token signatures, and MLS leaf node credentials use Ed25519.

**MLS ciphersuite:** MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (RFC 9420 §17.1). This provides: X25519 for key agreement (HPKE KEM), AES-128-GCM for symmetric encryption (AEAD), SHA-256 for hashing, Ed25519 for signing.

**DID-to-DID encryption:** HPKE (RFC 9180) with suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. Used for MLS Welcome messages. The HPKE suite matches the MLS ciphersuite to minimize the cryptographic surface area.

**Key distribution HPKE:** RFC 9180 Base mode for sender key (§9.16.2), access key (§9.17), and broadcast key (§5.14.2) distribution. The suite is identical to DID-to-DID encryption: DHKEM(X25519, HKDF-SHA256) (KEM ID: 0x0020), HKDF-SHA256 (KDF ID: 0x0001), AES-128-GCM (AEAD ID: 0x0001). AES-128-GCM is used (not AES-256-GCM) because the HPKE AEAD protects a single 32-byte key per operation — the 128-bit security level matches the X25519 KEM and is consistent with the MLS ciphersuite. Each key distribution protocol uses a distinct `info` string for domain separation (see §9.16.2, §9.17.1, §5.14.2). Nonces for the AEAD within HPKE are managed internally by RFC 9180 — implementations MUST NOT generate or supply external nonces for the HPKE AEAD. The HPKE `enc` (encapsulated key) and `ct` (ciphertext) are transmitted in the wire format as specified per protocol.

**Merkle tree hash:** SHA-256. Append-only log tree following Certificate Transparency structure (RFC 6962 §2). SCP uses the RFC 6962 hash construction with domain-separated leaf and interior node hashing to support efficient inclusion proofs and consistency proofs:

- **Leaf hash:** `SHA-256(0x00 || event_data)` — the `0x00` prefix byte identifies leaf nodes.
- **Interior node hash:** `SHA-256(0x01 || left_child_hash || right_child_hash)` — the `0x01` prefix byte identifies interior nodes.
- **Empty tree:** The Merkle root of an empty tree is defined as `SHA-256("")` (the hash of the empty string, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
- **Tree construction:** Events are appended as leaves in order. The tree is built incrementally — each new leaf extends the tree per RFC 6962 §2. The root is recomputed after each append.

The `0x00`/`0x01` domain separation prevents second-preimage attacks where an attacker constructs an interior node that is interpreted as a leaf (or vice versa). This is a critical security property: without it, an attacker could forge inclusion proofs by substituting tree layers.

The Merkle root provides tamper-evident integrity over the entire event history. Inclusion proofs (proving a specific event is in the log) require `O(log N)` hashes. Consistency proofs (proving one log state is an extension of another) also require `O(log N)` hashes. These are used for equivocation detection (§9.9) and context state verification (§7.3.1).

### 9.5.1 Canonical Hash Construction

All signed structures in the protocol use a single canonical hash construction. This ensures cross-implementation signature interoperability — two implementations that serialize the same logical data MUST produce identical bytes.

**Construction:** `SHA-256(domain_separator || field_1 || field_2 || ... || field_N)`

**Encoding rules:**

- **Domain separator:** UTF-8 string, no length prefix (the separator itself is fixed per struct version).
- **Variable-length bytes** (strings, byte arrays of unknown length): 4-byte big-endian length prefix followed by the raw bytes. `len(field) as u32` in network byte order.
- **Fixed-length bytes** (`[u8; 32]`, `[u8; 64]`): raw bytes, no length prefix. The length is known from the schema.
- **u64 integers:** 8 bytes, big-endian (network byte order).
- **u32 integers:** 4 bytes, big-endian.
- **u16 integers:** 2 bytes, big-endian.
- **Fixed-length bytes of other sizes** (`[u8; 16]`): raw bytes, no length prefix.
- **Optional fields:** if present, encoded as above. If absent, encoded as `SHA-256(0x00)` (32-byte sentinel). The sentinel is distinguishable from any real hash because `SHA-256(0x00)` is not a valid hash of structured data with a domain separator.

**Field ordering** is defined per struct and is part of the protocol specification. Changing the field order changes the hash. Fields are listed in the order specified below for each struct.

**Domain separator versioning:** each struct's domain separator includes a version suffix (e.g., `"SCP-INNER-ENVELOPE-V1:"`). Changing any field's encoding, adding a field, or removing a field requires incrementing the version. Old signatures become invalid — this is intentional.

**Reference implementation:** the migration proof (§9.12) uses this exact construction: `SHA-256("SCP-MIGRATION-V1:" || len(old_did) || old_did || len(new_did) || new_did || rotated_at)`.

**Additional signed structures** using this canonical hash construction are defined in their respective spec sections: `ResetRequest` (domain: `"SCP-RESET-REQUEST-V1:"`) is defined in §23.5.2.

### 9.5.2 Signed Structure Definitions

**InnerEnvelope** — domain: `"SCP-INNER-ENVELOPE-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `version` | 2-byte BE u16 |
| 2 | `message_type` | 1-byte U8 discriminator (0x00=Content, 0x01=Signaling, 0x02=KeyDistribution) |
| 3 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 4 | `sender_did` | 4-byte BE length + UTF-8 bytes |
| 5 | `epoch` | 8-byte BE u64 |
| 6 | `generation_number` | 8-byte BE u64 |
| 7 | `sequence_number` | 8-byte BE u64 |
| 8 | `timestamp` | 8-byte BE u64 |
| 9 | `payload_hash` | 4-byte BE length + 32 bytes |
| 10 | `provenance_hash` | 4-byte BE length + 32 bytes (or `SHA-256(0x00)` sentinel if absent) |
| 11 | `signing_key_id` | 4-byte BE length + UTF-8 bytes |

Note: `version` (position 1) commits the protocol version to the signature. `message_type` (position 2) is a discriminator byte that prevents type-flipping attacks where an adversary replays a message under different type semantics (#290). `signing_key_id` is last (position 11) to match the existing implementation. It binds the signature to the specific verification method (`#active` or `#agent`, ADR-039), preventing key confusion attacks.

The outer envelope is unsigned — it contains only the routing pseudonym, recipient hint, blob TTL, and encrypted blob (§9.10.2). The full signature lives inside the encrypted payload, signed by `#active` (Active Signing Key) or `#agent` (Agent Signing Key) from the sender's DID document (ADR-039). The domain separator prevents cross-protocol hash confusion. Field-swapping attacks (e.g., moving a payload from one context to another) produce invalid signatures. Relay operators cannot verify signatures (they cannot see sender DIDs) — verification is the responsibility of context members who can decrypt the payload.

**BroadcastEnvelope** — domain: `"SCP-BROADCAST-ENVELOPE-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 2 | `sender_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `signing_key_id` | 4-byte BE length + UTF-8 bytes |
| 4 | `sequence` | 8-byte BE u64 |
| 5 | `key_epoch` | 8-byte BE u64 |
| 6 | `timestamp` | 8-byte BE u64 |
| 7 | `content_hash` | 32 bytes (SHA-256 of original plaintext) |
| 8 | `provenance_hash` | 32 bytes (SHA-256 of serialized provenance, or `SHA-256(0x00)` if absent) |

Note: the current implementation uses AEAD authentication only; the full signed structure above is the target format. The `BroadcastEnvelope` struct will be expanded to include all fields per #352.

The AEAD nonce is intentionally excluded from the canonical hash. The AEAD authentication tag already authenticates the nonce as part of the encryption — including it in the signed hash would be redundant and would create a second binding that must be kept consistent without providing additional security.

The signature is verified by subscribers against the author's Active Signing Key or Agent Signing Key (resolved from the author's DID document, ADR-039).

**SenderKeyEpochAdvance** — domain: `"SCP-EPOCH-ADVANCE-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 2 | `sender_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `"key_epoch"` | literal ASCII bytes (domain separation within the hash) |
| 4 | `epoch` | 8-byte BE u64 |
| 5 | `signer_key_ref` | 4-byte BE length + UTF-8 bytes (`#active` or `#agent`, prevents key confusion) |

**SenderKeyRequest** — domain: `"SCP-KEY-REQUEST-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `requester_did` | 4-byte BE length + UTF-8 bytes |
| 2 | `sender_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `epoch` | 8-byte BE u64 |
| 4 | `wrapping_pubkey` | 4-byte BE length + raw bytes |
| 5 | `nonce` | 16 bytes (fixed-size CSPRNG, prevents replay) |
| 6 | `timestamp` | 8-byte BE u64 |

Note: `context_id` is not in the current signed hash (the request struct does not carry it). Adding it is tracked by #346.

**Attestation** — domain: `"SCP-ATTESTATION-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `id` | 4-byte BE length + UTF-8 bytes |
| 2 | `attestation_type` | 2-byte BE u16 (attestation type tag per `attestation_type_tag()`) |
| 3 | `issuer` | 4-byte BE length + UTF-8 bytes (DID) |
| 4 | `subject` | 4-byte BE length + UTF-8 bytes (DID) |
| 5 | `claim` | 4-byte BE length + UTF-8 bytes (compact JSON — see note) |
| 6 | `evidence` | 4-byte BE length + raw bytes if present, or `SHA-256(0x00)` sentinel if absent |
| 7 | `issued_at` | 8-byte BE u64 |
| 8 | `expires_at` | 8-byte BE u64 if present, or `SHA-256(0x00)` sentinel if absent |
| 9 | `revocation_status` | 4-byte BE length + MessagePack bytes of `RevocationStatus` enum |

Note: the `claim` field uses compact JSON with no whitespace (equivalent to Python `json.dumps(separators=(',', ':'))`). JSON key ordering within claim objects is NOT guaranteed deterministic across implementations — claims with nested objects should use only flat key-value structures or pre-serialized byte strings. The `evidence` field, when present, is serialized as MessagePack bytes of the `AttestationEvidence` struct. The `revocation_status` field is always present (never absent) — `Active` serializes as a distinct MessagePack value from `Revoked{...}`. Including `revocation_status` in the signed scope prevents an intermediary from flipping Active↔Revoked without invalidating the signature (§7.4.1).

**ParticipationProfile** — domain: `"SCP-PARTICIPATION-PROFILE-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `subject_did` | 4-byte BE length + UTF-8 bytes |
| 2 | `signer_public_key` | 32 bytes |
| 3 | `participation_duration_secs` | 8-byte BE u64 |
| 4 | `governance_actions_against` | 8-byte BE u64 |
| 5 | `governance_actions_by` | 8-byte BE u64 |
| 6 | `tool_invocation_count` | 8-byte BE u64 |
| 7 | `context_creation_count` | 8-byte BE u64 |
| 8 | `role_progression_count` | 8-byte BE u64 |
| 9 | `attestation_count` | 8-byte BE u64 |
| 10 | `updated_at` | 8-byte BE u64 |
| 11 | `event_log_root` | 32 bytes |

**BlockNotification** — domain: `"SCP-BLOCK-NOTIFICATION-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 2 | `blocker_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `blocked_did` | 4-byte BE length + UTF-8 bytes |
| 4 | `signing_key_id` | 4-byte BE length + UTF-8 bytes (`"#active"` or `"#agent"`) |
| 5 | `timestamp` | 8-byte BE u64 |

**AccessKeyRequest** — domain: `"SCP-ACCESS-KEY-REQUEST-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 2 | `requester_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `timestamp` | 8-byte BE u64 |
| 4 | `wrapping_pubkey` | 32 bytes (X25519 public key) |
| 5 | `nonce` | 16 bytes (random, unique per request) |

**GovernanceProposal ID** — domain: `"SCP-PROPOSAL-V1:"` (hash, not signature)

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 2 | `proposer_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `action_bytes` | 4-byte BE length + canonical JSON serialization of `GovernanceAction` (compact, no whitespace) |
| 4 | `timestamp` | 8-byte BE u64 |

Note: The `ProposalId` is the SHA-256 output (32 bytes). It is deterministic for identical inputs and collision-resistant across contexts. The `action_bytes` field uses **canonical JSON** serialization of the `GovernanceAction` enum (externally tagged, compact format with no whitespace — equivalent to `json.dumps(separators=(',', ':'))` in Python). JSON is used rather than MessagePack because `GovernanceAction` is a complex 30-variant enum whose serialized form must be byte-identical across all SDK implementations. MessagePack has no canonical form standard and field ordering varies by library; JSON serialization is more predictable across languages and has RFC 8785 (JCS) as a formal canonicalization standard. This is consistent with all other cross-implementation canonical hashing in the protocol: handle tool signing (§22), app declarations (§8.4), DID documents (§18.1), and governance config hashing for multi-parent contexts (§5.13).

**SignedVote** — domain: `"SCP-VOTE-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `proposal_id` | 32 bytes (fixed-size, the `ProposalId` hash) |
| 2 | `voter_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `vote_type` | 4-byte BE length + JSON serialization of `VoteType` (compact, no whitespace) |
| 4 | `timestamp` | 8-byte BE u64 |

Note: The Ed25519 signature is over `SHA-256("SCP-VOTE-V1:" || fields)`. The `proposal_id` binds the vote to a specific proposal, preventing cross-proposal replay. `VoteType` is serialized as compact JSON (equivalent to `json.dumps(separators=(',', ':'))` in Python).

**UCAN signing:** EdDSA (Ed25519) per UCAN specification. The nonce field (`nnc`) is mandatory and must be unique per token issuance. This prevents UCAN token replay. UCAN token expiry (`exp`) MUST NOT exceed 24 hours (matching the nonce deduplication cache window in §9.8.2). Tokens with longer expiry could be replayed after nonce cache eviction. **UCAN revocation** is per-context via `RevocationList` — an append-only map of token CIDs to revocation states (Active, RevocationPending, Revoked). Revocations are distributed as MLS application messages to all context members. Revocation check is step 10 of the 11-step validation pipeline (ADR-016) and is performed on every capability exercise. The system is **fail-closed**: tokens in `RevocationPending` state (revocation initiated but not yet confirmed via MLS) are denied. See ADR-016 criterion 7 and `scp-core/crypto/ucan/revoke.rs` for the full specification.

**UCAN CID computation.** UCAN tokens are identified by Content Identifiers (CIDs) in the `RevocationList` and in delegation chain `prf` references. CID computation MUST use the following parameters:

- **CID version:** CIDv1 (multicodec prefix `0x01`).
- **Hash algorithm:** SHA-256 (multihash code `0x12`, digest length 32 bytes).
- **Content codec:** DAG-CBOR (`0x71`). The UCAN payload (header + claims, excluding the signature) is serialized to canonical CBOR (RFC 8949 deterministic encoding, §4.2) before hashing. This ensures that CIDs are computed over a deterministic byte representation regardless of the original token encoding (JWT string vs. binary).
- **Serialization order for CID computation:** The UCAN payload fields are serialized in lexicographic key order per DAG-CBOR conventions: `att`, `aud`, `exp`, `fct` (if present), `iss`, `nbf` (if present), `nnc`, `prf`. This is the canonical field set from UCAN 0.10+.
- **Multibase encoding:** `base32lower` (multibase prefix `b`) for display and logging. Raw CID bytes (no multibase prefix) for wire format in `RevocationList` entries, `prf` references, and MLS application messages.
- **Implementation note:** The CID is computed over the UCAN payload only (not the full JWT including the signature), because the payload uniquely identifies the token's claims and the signature is verifiable separately. Two tokens with identical payloads but different signatures (e.g., reissued after key rotation) produce the same CID — this is intentional and ensures that revocations target the claim content, not the cryptographic binding.

**Why single ciphersuite:** Ciphersuite negotiation adds complexity and introduces downgrade attack vectors. For v1, every implementation uses exactly these algorithms. Future protocol versions may introduce additional ciphersuites with a secure negotiation mechanism, but v1 prioritizes simplicity and auditability.

## 9.6 Identity Verification and MITM Prevention

Identity verification is the trust root for the entire protocol. If an attacker can substitute their public key for another identity's, every layer above — encryption, authentication, capability validation — is compromised. This section specifies how SCP prevents MITM attacks on identity resolution.

### 9.6.1 did:dht Self-Certification

The did:dht method (target DID method for SCP) is **self-certifying**: the DID string itself is the z-base-32 encoding of the Ed25519 public key. When resolving a did:dht identifier:

1. The client queries the Mainline DHT for the BEP44 signed record associated with the DID.
2. The client verifies the BEP44 record signature against the public key encoded in the DID string.
3. If the signature is valid, the DID document is authentic. No trusted third party is required.

**MITM on did:dht resolution is impossible given the correct DID.** A DHT node cannot serve a fraudulent DID document because the document must be signed by the key embedded in the DID itself. Tampering is detectable without trusting any intermediary.

**Stale document prevention:** BEP44 records include a sequence number. The client MUST reject DID documents with a lower sequence number than previously observed for the same DID. This prevents serving outdated documents.

**The remaining question:** "Is this the right DID?" Self-certification proves the binding between a DID and its key, but cannot prove the binding between a DID and a person. This is an out-of-band verification problem addressed by Key Continuity Verification (§9.11).

**Relay-stored DID documents.** Self-certification applies equally to DID documents stored on SCP relays (§3.10.2). The BEP44 signature is verified against the public key encoded in the DID string regardless of whether the document was retrieved from the Mainline DHT or an SCP relay. The storage backend does not affect the trust model.

### 9.6.2 did:web Security Properties and Limitations

did:web (fallback only — used only if did:dht libraries prove unusable) resolves via HTTPS to a well-known path on the authority domain. Security depends on DNS integrity, TLS certificate validity, and server integrity.

**did:web is NOT self-certifying.** A compromised server, DNS hijack, or CA compromise can serve a fraudulent DID document indistinguishable from a legitimate one. did:web introduces a server dependency that contradicts SCP's infrastructure-minimal design. It exists as a contingency fallback, not a planned deployment path.

**Required mitigations if did:web is used:**

- The SDK MUST pin the TLS certificate of the did:web resolution server.
- The SDK MUST verify each verification method independently — track `#0` (Identity Key), `#active` (Active Signing Key), and `#agent` (Agent Signing Key) separately for TOFU pinning (ADR-039). A change in any single VM triggers the key change alert, even if others remain stable.
- The SDK MUST alert the user on any key change, with maximum severity.
- The SDK SHOULD record the did:web key fingerprint in identity private state (§3.7) for cross-device consistency of TOFU state.

**Migration from did:web to did:dht (if fallback was used):** If a deployment started with did:web as a fallback, migration to did:dht must be signed by the old did:web key, creating a verifiable authorization chain: "the identity formerly at did:web:example.com is now at did:dht:z6Mk...". Both DIDs temporarily resolve to the same public key during the transition. This migration path exists for contingency recovery, not as a planned lifecycle.

### 9.6.3 Relay List Authentication

A DID's relay list (service endpoints) is published in the DID document.

**For did:dht:** The relay list in the DID document is self-certified (BEP44 signature). Substituting a relay list requires the identity's private key.

**For transport adapters with native relay lists:** Some transport adapters (e.g., Nostr via NIP-65) publish relay lists in transport-specific formats signed by a keypair derived from the DID key. This provides relay list authentication independent of the DID method but is adapter-specific, not a protocol requirement.

**Attack: relay list substitution.** A compromised DHT node or relay could serve a stale relay list, directing messages to relays the recipient no longer uses. Defense: sequence numbers in BEP44 records ensure freshness. Clients MUST reject relay lists with lower sequence numbers than previously observed.

### 9.6.4 First-Contact Trust Bootstrapping

When Alice first encounters Bob's DID (via shared context membership, registry discovery, or referral):

- **For did:dht:** Alice resolves the DID document and verifies it against the DID string. The binding is cryptographically verified. No MITM is possible.
- **For did:web:** Alice resolves over HTTPS and trusts the web PKI. The SDK records Bob's key on first contact (TOFU) and alerts on any subsequent change.

## 9.7 Group Key Management — MLS Integration

MLS (RFC 9420) provides the group encryption layer for SCP. This section specifies how MLS concepts map to SCP and what security properties the SDK must enforce.

### 9.7.1 MLS-to-SCP Concept Mapping

| MLS Concept | SCP Concept | Notes |
|---|---|---|
| Group | Context | 1:1 mapping. Each SCP context is one MLS group. |
| Member (LeafNode) | Agent (in context) | One MLS leaf node per agent in the context. |
| Epoch | Context epoch | Increments on every membership change or key update. Included in all SCP envelopes. |
| LeafNode credential | DID + UCAN + signing_key_id | The MLS credential field contains the member's DID, their context-scoped UCAN token, and the `signing_key_id` (`#active` or `#agent`) identifying which verification method signed this leaf node (ADR-039). |
| Welcome message | Context join token | HPKE-encrypted to new member's KeyPackage. Contains the group state needed to decrypt future messages. |
| KeyPackage | Pre-key bundle | Published to relays so others can add the identity to groups even when offline. Signed by the Active Signing Key (`#active`) or Agent Signing Key (`#agent`) — NOT the Identity Key (`#0`). Single-use. See note below. |
| Proposal (Add/Remove/Update) | Governance action | MLS membership proposals map to SCP membership changes. |
| Commit | Governance commit | Finalizes pending proposals and advances the epoch. |
| Application message | SCP envelope payload | The encrypted content within an SCP envelope. |
| Delivery Service (DS) | SCP relay(s) | The untrusted store-and-forward layer. Any transport adapter (native relay, Nostr, Matrix, etc.) serves this role. |
| Authentication Service (AS) | DID resolution + UCAN validation | SCP's identity layer serves as MLS's AS. No separate trusted server. |

**KeyPackage signing key.** Per RFC 9420 §10.1, the signature key in a KeyPackage's `leaf_node` field is the key used to sign the KeyPackage. In SCP, this is the Active Signing Key (`#active`) for human-initiated joins, or the Agent Signing Key (`#agent`) for agent-initiated joins (ADR-039). The Identity Key (`#0`) is NOT used for KeyPackage signing — `#0` is reserved exclusively for DID document operations and pre-rotation commitments (ADR-003). Using `#active` or `#agent` for KeyPackages is consistent with the MLS credential model: the `leaf_node` credential contains the `signing_key_id` field (`#active` or `#agent`), and the KeyPackage signature MUST be verifiable against the corresponding verification method in the signer's DID document. On key rotation (§9.12), all outstanding KeyPackages signed by the old key MUST be deleted from relays and replaced with KeyPackages signed by the new key.

**Group context extensions for nesting.** Child contexts include parent context IDs and governance configuration hashes in the MLS `group_context` extensions field (§5.13.3). This cryptographically binds the parent lineage to the child's group identity — the derived `group_id` is a function of the parent references. Root contexts (no parents) have empty nesting extensions.

**Authentication Service design:** MLS delegates identity verification to an Authentication Service (AS). In SCP, the AS is fully decentralized: DID resolution provides the public key binding, and UCAN validation provides the capability binding. No centralized AS server exists. Each participant independently verifies credentials by resolving the DID and validating the UCAN chain.

### 9.7.2 Forward Secrecy

MLS provides forward secrecy through epoch-based key ratcheting. After a Commit message advances the group to a new epoch, key material from old epochs is deleted.

**SDK requirements:**

- The SDK MUST delete old epoch key material after processing a Commit, subject to a **grace window** for in-flight messages. Old epoch keys are retained in volatile memory only (never persisted) for the shorter of: (a) all members have sent at least one message in the new epoch, or (b) 30 seconds from local Commit processing time. After the grace window closes, old epoch secrets, application key schedules, and ratchet tree states for past epochs are destroyed and MUST NOT be recoverable. See ADR-001 criterion 6 for the full grace window specification.
- Historical epoch keys MUST be treated as equivalent to ephemeral Diffie-Hellman parameters: used once, then destroyed.
- Members who want to re-read historical messages must retain the decrypted plaintext locally. They cannot re-derive old epoch keys from current state.

**Interaction with memory scope:**

- For `full` memory scope contexts: forward secrecy protects against future key compromise revealing past messages. Members retain plaintext locally if they want to re-read.
- For `ephemeral` memory scope contexts: the MLS group state is destroyed on context close. This is the `destroy_keys` operation — destroy tree root, all epoch secrets, all application key material. All historical messages become physically unreadable.
- For `summary` memory scope contexts: same as ephemeral, but a summary is generated and verified before destruction.

### 9.7.3 Post-Compromise Security (PCS)

MLS provides PCS through the Update proposal mechanism. After a member sends an Update (generating a fresh HPKE key pair and ratcheting their path in the tree), any previous compromise of that member's state becomes useless for future messages.

**SDK requirements:**

- The SDK MUST periodically issue MLS Update proposals. Recommended interval: every 24 hours for active contexts, or immediately after any suspected compromise.
- The SDK SHOULD issue an Update after re-establishing connectivity following an offline period.
- When an Active Signing Key rotates (ADR-003 §4a), the agent MUST issue an MLS Update in every active context with the new credential. This synchronizes key rotation with MLS-level post-compromise security.
- When an Agent Signing Key rotates (ADR-039), the SDK MUST issue an MLS Update proposal in every active context with a new credential containing the updated `signing_key_id` referencing the new `#agent` verification method. This ensures peers can verify messages signed by the new agent key and reject messages signed by the old one.
- When an Identity Key migrates (ADR-003 §4b), the agent MUST send a `DidRotationEvent` in every active context and issue MLS Updates with the new credential under the new DID.

**PCS Update interval as context parameter:** High-security contexts may configure shorter PCS Update intervals (e.g., 1 hour). The interval is a context-level parameter set at creation, defaulting to 24 hours.

### 9.7.4 Key Lifecycle

**Key generation:**

- Identity Key (Ed25519): Generated in hardware security module where available (Secure Enclave, Android Keystore). Private key never exported from the secure element. Used ONLY for DID document updates and signing pre-rotation commitments. The DID string is derived from this key and never changes.
- Active Signing Key (Ed25519): Generated via KeyCustody. Used for MLS credentials, inner envelope signatures, UCAN issuance. Rotatable via DID document update signed by the Identity Key (ADR-003 §4a). The DID string does NOT change on active key rotation.
- Pre-Rotation Key (Ed25519): Generated at identity creation, stored in cold/offline custody (see §9.7.4.1 for custody requirements). `SHA-256(public_key)` is published as a PreRotationCommitment in the DID document. Revealed only during Identity Key migration (ADR-003 §4b) to prove legitimate rotation.
- Agent Signing Key (Ed25519, optional): Generated by agent runtime software. Published as `#agent` verification method in the DID document by the Identity Key (`#0`). Software-held — no HSM requirement (agent runtimes typically lack hardware security). Used for agent-autonomous message signing and scoped UCAN delegation. Rotatable via DID document update signed by `#0` (ADR-039). The DID string does NOT change on agent key rotation.
- MLS leaf key (X25519): Generated by the MLS library per the selected ciphersuite. Stored in platform secure storage.
- KeyPackages: Pre-generated and published to relays. Each KeyPackage is single-use. The SDK MUST maintain a buffer of at least 10 unused KeyPackages per identity on relays. Replenished when the buffer drops below 5.
- UCAN signing key: Active Signing Key (Ed25519) for root UCANs. UCAN tokens are signed by the human's Active Signing Key — NOT the Identity Key (ADR-003 §4a). On active key rotation, existing UCAN tokens are revoked and reissued under the new Active Signing Key. Agent-autonomous actions use scoped UCANs delegated from `#active` to `#agent` with `fct.scp_key_scope: "#agent"` (ADR-039). The agent signs these scoped UCANs with its `#agent` key — never the root UCAN directly.

**Key distribution:**

- Identity public key: Distributed via DID document (DHT resolution or web resolution).
- KeyPackages: Published to relays via the transport adapter. Any party wanting to add this identity to a group fetches a KeyPackage from their relay.
- Context group key: Distributed via MLS Welcome message, encrypted to the new member's KeyPackage. Only the intended recipient can decrypt.

**Key rotation:**

- Active Signing Key: Rotated via `rotate_active_key` (ADR-003 §4a). DID document is updated with new verification method, signed by the Identity Key, published to DHT with incremented sequence number. All active MLS groups receive an Update proposal with the new credential. The DID string does NOT change.
- Agent Signing Key: Rotated via `rotate_agent_key` (ADR-039). The Identity Key (`#0`) publishes a new DID document with a replacement `#agent` verification method (or removes `#agent` entirely to revoke agent access). All scoped UCANs with `fct.scp_key_scope: "#agent"` signed by the old `#agent` key are revoked and reissued with the new key. All active MLS groups receive an Update proposal with a new credential containing the updated `signing_key_id`. The DID string does NOT change.
- Identity Key: Migrated via `migrate_identity` (ADR-003 §4b) — rare operation. Creates a new DID with the pre-rotation key as the new Identity Key. Old DID document updated with `alsoKnownAs` forwarding. `DidRotationEvent` sent to all active contexts. Pre-rotation proof resolves ambiguity if the old key was compromised. The migration proof is an Ed25519 signature over `SHA-256(SCP-MIGRATION-V1: || len(old_did) || old_did || len(new_did) || new_did || rotated_at)` where `len()` is a 4-byte big-endian unsigned integer and `rotated_at` is an 8-byte big-endian Unix timestamp. Length prefixes prevent concatenation ambiguity between variable-length DID strings.
- MLS epoch keys: Rotated automatically on every Commit (membership change or Update).
- UCAN tokens: Expire per their `exp` field. Re-issued by the human's Active Signing Key. On active key rotation (ADR-003 §4a), all UCAN tokens signed by the old Active Signing Key are revoked and reissued under the new key. On agent key rotation (ADR-039), all scoped UCANs with `fct.scp_key_scope: "#agent"` are revoked and reissued with the new `#agent` key; root UCANs signed by `#active` are unaffected. Revocations are added to the per-context `RevocationList` and distributed as MLS application messages (see §9.5 UCAN revocation, ADR-016 criterion 5).

**Key destruction:**

- Ephemeral context close: Destroy MLS group state — tree secrets, all epoch key schedules, application key material. See §9.15 for destruction verification.
- KeyPackage consumption: After a KeyPackage is used in a Welcome message, the SDK deletes the KeyPackage's private key. One-time use is mandatory.
- Old epoch material: Destroyed after Commit processing (forward secrecy, §9.7.2).

### 9.7.4.1 Pre-Rotation Key Custody

The pre-rotation key is the security backstop for the entire identity system — the last resort for recovery after Identity Key compromise (§9.12). Its custody MUST be specified with the same rigor as the Identity Key.

**Custody requirements:**

1. **Generation.** The pre-rotation keypair MUST be generated on the device during identity creation, using the platform's CSPRNG. The private key MUST NOT be generated on a remote server.

2. **Commitment publication.** `SHA-256(pre_rotation_public_key)` is published as a `PreRotationCommitment` service endpoint in the DID document (§18.2.2). Only the hash is published — the public key itself is never published until the pre-rotation key is used.

3. **Storage isolation.** The pre-rotation private key MUST be stored separately from the Identity Key and Active Signing Key. It MUST NOT be accessible through the same custody provider or authentication flow used for daily operations. This ensures that compromise of the operational custody path does not compromise the recovery path.

4. **Approved custody methods** (ordered by security, any one is sufficient):

   | Method | Security level | Description |
   |--------|---------------|-------------|
   | Hardware security key (FIDO2/U2F) | Highest | Pre-rotation key stored on a dedicated hardware security key (e.g., YubiKey). The key never leaves the hardware. Requires physical possession for recovery. |
   | Secondary device secure enclave | High | Pre-rotation key stored in the secure enclave of a device NOT used for daily SCP operations (e.g., a tablet kept at home while the phone is the daily driver). |
   | Platform-backed cloud key store | Medium | Pre-rotation key stored in platform key backup (iCloud Keychain with Advanced Data Protection, Google Cloud Key Vault). Recoverable through platform account recovery. |
   | Encrypted offline backup | Medium | Pre-rotation private key encrypted with AES-256-GCM using a key derived from a user-chosen passphrase via Argon2id (memory: 64 MiB, iterations: 3, parallelism: 4). The encrypted backup is stored offline (USB drive, printed QR code, or secure note). The SDK MUST generate the passphrase with at least 128 bits of entropy if auto-generated. |
   | Shamir secret sharing (3-of-5) | Medium | Pre-rotation private key split into 5 shares using Shamir's Secret Sharing (GF(2^8)), with any 3 shares sufficient to reconstruct. Shares distributed to trusted contacts or stored in geographically separate locations. Each share is 33 bytes (1 byte share index + 32 bytes share data). |
   | Paper backup (BIP39 mnemonic) | Lowest acceptable | Pre-rotation private key encoded as a 24-word BIP39 mnemonic phrase. Stored physically (written, printed, engraved). The SDK MUST warn users that loss of the paper backup eliminates the pre-rotation recovery path. |

5. **SDK presentation.** At identity creation, the SDK MUST:
   a. Generate the pre-rotation keypair.
   b. Present the user with custody options (ordered by security as above).
   c. Guide the user through the selected custody method.
   d. Verify the backup (for offline methods: require the user to re-enter or re-scan the backup before proceeding).
   e. Publish the `PreRotationCommitment` to the DID document only after backup verification succeeds.
   f. Destroy the pre-rotation private key from the creating device's memory after backup is confirmed.

6. **Post-rotation key cycling.** After a pre-rotation key is used for Identity Key migration (§9.12), the protocol MUST immediately generate a new pre-rotation keypair, guide the user through custody selection again, and publish a new `PreRotationCommitment`. The old pre-rotation key is destroyed after migration completes.

7. **Custody status tracking.** The SDK SHOULD periodically prompt the user to verify their pre-rotation key backup is still accessible (e.g., every 6 months). This is a client-level reminder, not a protocol-level enforcement — the protocol cannot verify that an offline backup still exists.

**Failure modes:**

- **Pre-rotation backup lost, Identity Key intact:** No immediate impact. The identity continues to function. The user has lost their recovery backstop. The SDK SHOULD warn that identity recovery from compromise is no longer possible and guide the user to generate a new pre-rotation keypair.
- **Pre-rotation backup lost, Identity Key compromised:** Social recovery (§3.3) is the only remaining path. Trusted contacts with admin roles must remove the compromised identity and re-add under a new DID.
- **Pre-rotation key compromised (but Identity Key intact):** The user MUST immediately generate a new pre-rotation keypair and publish a new `PreRotationCommitment` to their DID document. The old pre-rotation commitment is superseded by the new one.

## 9.8 Message Security

This section specifies how SCP prevents message forgery, replay attacks, and ordering manipulation.

### 9.8.1 Envelope Integrity (Two Independent Checks)

Every SCP message has two independent integrity verifications, both inside the encrypted payload. Neither is verifiable by relays — relays see only opaque blobs.

**Inner check 1 — Ed25519 identity signature.** The sender signs the payload with their Active Signing Key or Agent Signing Key (see ADR-003 §4a, ADR-039): `SHA256(context_id || sender_did || epoch || generation || sequence || timestamp || payload_hash || provenance_hash)` where `payload_hash` covers the original plaintext (before padding) and `provenance_hash` covers serialized provenance metadata (or `SHA256(0x00)` if absent). Processing order: hash plaintext -> hash provenance -> sign -> pad -> sender-key encrypt -> MLS encrypt. Reverse on receipt: MLS decrypt -> sender-key decrypt -> strip padding -> verify signature -> verify payload_hash -> verify provenance_hash. A failed signature means the envelope was tampered with or forged and MUST be rejected.

**Inner check 2 — MLS membership_tag.** The MLS PrivateMessage format includes an HMAC (membership_tag) that proves the sender is a group member with correct epoch secrets. This is verified during MLS decryption. It provides authentication independent of the identity signature — even if an attacker obtained the DID private key, they cannot produce a valid membership_tag without the MLS epoch secrets.

Both checks MUST pass for a message to be accepted. This defense-in-depth means an attacker must compromise BOTH the identity key AND the MLS group state to forge a message. Both checks are member-only verifiable — the outer envelope is unsigned by design (§9.10.2), ensuring relays learn nothing about message authenticity or sender identity.

### 9.8.2 Replay Prevention (Three-Layer Defense)

**(a) MLS generation numbers.** MLS assigns each sender a generation counter that increments with every message. Recipients track the highest generation number seen per sender per epoch. A message with a generation number less than or equal to the highest seen is a replay and MUST be rejected. This catches exact replays within a single MLS epoch.

**(b) Hash-based deduplication.** The SDK maintains a deduplication cache keyed by `SHA256(encrypted_blob)` — the hash of the outer envelope's encrypted blob, which is visible without decryption. Any envelope with a previously-seen blob hash is a replay and MUST be dropped silently. Cache size: bounded by a sliding window of the most recent 10,000 envelopes or 24 hours, whichever is larger. This catches replays across MLS epochs.

**(c) Timestamp bounds.** Every SCP envelope includes a `created_at` timestamp. Recipients MUST reject envelopes with timestamps more than 5 minutes in the future (clock skew tolerance). Within a sequence of messages from the same sender in the same context, timestamps must be monotonically non-decreasing within the clock skew tolerance. This catches time-shifted replays.

The past-bound is relative, not absolute, to handle offline delivery: if Bob comes online after 3 hours, he accepts messages from the past 3 hours. But timestamps from a single sender must not regress.

**Broadcast mode replay prevention.** Broadcast contexts use the same three-layer defense with the following mode-specific adaptations: (a) No MLS generation numbers — broadcast uses per-sender SCP sequence numbers as the primary per-sender ordering mechanism. (b) Hash-based deduplication operates identically on outer envelope blob hashes. (c) Timestamp bounds are identical. Additionally, the `key_epoch` field in `BroadcastEnvelope` provides a fourth signal: a message encrypted with an epoch lower than the subscriber's current cached epoch for that author is suspect (may be a replay of pre-rotation content).

### 9.8.3 Message Ordering

Within a context, messages are ordered by: `(epoch, sender_generation_number, timestamp)`. This gives a total order per-sender and a causal order across senders — epoch boundaries are synchronization points.

The Merkle event log records events in append order. Each event references the previous event's hash, creating a hash chain. If two events reference the same parent, the log has forked — possible equivocation (see §9.9).

**Interaction with relay ordering:** Relays do not guarantee message ordering. The SDK MUST re-order messages locally using `(epoch, generation, timestamp)` before presenting them to the application layer.

**Authoritative ordering:** The Merkle log order is authoritative, not timestamps. Timestamps are hints for the SDK to reconstruct order in real-time. Once events are committed to the log, the log order is the permanent record.

### 9.8.4 Forgery Prevention

**Message forgery:** Prevented by Ed25519 inner signature + MLS membership_tag. Both checks are inside the encrypted payload (§9.8.1). An attacker who does not hold a member's private key cannot produce a valid inner envelope, and an attacker without MLS epoch secrets cannot produce a valid membership_tag.

**Attestation forgery:** Attestations (§7.4) are signed by their issuer's DID key. Forgery requires the issuer's private key.

**UCAN forgery:** UCAN tokens contain a delegation chain where each delegation is signed. The mandatory `nnc` (nonce) field prevents token reuse outside the intended scope.

**Provenance forgery:** Data provenance records (§7.7) are attached by the SDK and signed as part of the enclosing envelope. An agent cannot fabricate a provenance claim for data sourced from a context it was never in, because provenance records are verifiable against the source context's Merkle root (for persistent-scope sources).

### 9.8.5 Sequence Validation

Each sender in a context maintains a monotonically increasing SCP sequence number (distinct from MLS generation numbers, which are MLS-internal). This sequence number is included in the envelope and the Merkle event log entry.

Recipients MUST accept all authenticated messages regardless of sequence order and apply reorder-before-delivery semantics. Multi-relay delivery (§10.4, ADR-012) guarantees that messages may arrive out of order; strict rejection would cause guaranteed message loss.

**Reorder buffer.** Each recipient maintains a per-(context, sender) reorder buffer:

- Messages arriving in order (sequence == expected next) are delivered immediately to the application layer.
- Messages arriving ahead of their predecessors (sequence > expected next) are buffered pending delivery of the missing predecessors.
- When a buffered message's predecessors arrive, the entire contiguous run is delivered in sequence order.
- **Gap timeout:** If a gap persists for more than 30 seconds, the recipient raises a suppression alert (§9.9), delivers all buffered messages (recording the gap in the event log), and advances the expected sequence number past the gap.
- **Buffer bound:** The reorder buffer is bounded at 100 messages per sender per context to prevent resource exhaustion. If the buffer fills, the oldest gap is force-closed (with suppression alert) and buffered messages are delivered.
- A duplicate sequence number indicates replay (caught by §9.8.2).

## 9.9 Relay Threat Model and Mitigations

Relays are untrusted infrastructure (§10.4). This section formally defines the relay threat model and specifies mitigations.

### 9.9.1 Relay Capabilities and Limitations

A relay CAN:

- **Read metadata:** routing IDs (per-context pseudonyms, §9.10.4), recipient hints (pseudonyms), blob TTLs, padded blob sizes, and connection timing. Context IDs, sender/recipient DIDs, and timestamps are inside the encrypted payload and NOT visible to relays (§9.10.2). Relay CANNOT read encrypted content.
- **Drop messages (suppression):** Silently discard envelopes. The sender believes delivery succeeded; the recipient never sees the message.
- **Delay messages:** Hold envelopes and deliver them later. Architecturally identical to slow network conditions.
- **Replay messages:** Re-deliver previously delivered envelopes. Mitigated by §9.8.2.
- **Equivocate:** Show different message histories to different members of the same context.
- **Correlate traffic:** Link activities across contexts based on timing, DID, and connection patterns.
- **Identify broadcast authors (Broadcast mode only):** In broadcast contexts, the `BroadcastEnvelope` sender DID is visible to relays (not hidden inside MLS encryption). This is an accepted tradeoff — broadcast authors are public figures whose identity is part of the content's value. Relay operators see who is publishing to a broadcast context, but cannot read the encrypted content.

A relay CANNOT:

- **Forge messages.** Requires the sender's private key (for the inner Ed25519 signature, §9.8.1) and MLS epoch secrets (for the membership_tag).
- **Decrypt content.** Requires MLS group key and sender-side key (§9.16).
- **Modify messages.** Inner signature verification and MLS membership_tag verification fail after decryption.
- **Inject members into contexts.** Requires MLS Welcome message encrypted to the joiner's KeyPackage.
- **Read broadcast content.** Broadcast content is AES-256-GCM encrypted with author broadcast keys. Relays see encrypted blobs and author DIDs, but cannot decrypt without the broadcast key (which is distributed only to registered, non-blocked subscribers via HPKE).

### 9.9.2 Suppression Detection

**Sequence gap detection:** If a recipient expects sequence #47 from a sender but receives #49, sequences #47 and #48 were suppressed (or delayed). The SDK MUST track expected sequence numbers per (context, sender) pair and alert on gaps.

**Heartbeat messages:** In active contexts, the SDK SHOULD send periodic heartbeat envelopes (recommended interval: 60 seconds when the context has active participants). A heartbeat is a minimal MLS application message with a sequence number but no user content. If heartbeats stop arriving from a participant who was recently active, suppression is suspected.

**Multi-relay cross-check:** Context messages SHOULD be published to at least 2 relays (recommended: 3). Recipients subscribe to all relays in the sender's relay list and merge received envelopes. If relay A delivers an envelope and relay B does not, this is an inconsistency. After a timeout (recommended: 30 seconds), the inconsistent relay is marked as potentially adversarial.

**Response to suspected suppression:** The SDK SHOULD alert the user and attempt delivery via alternative relays. The SDK MUST NOT silently discard the suspicion.

### 9.9.3 Equivocation Detection — Relay Consistency Protocol

The Relay Consistency Protocol detects relay equivocation — a relay showing different event histories to different members.

**Consistency checkpoints:** At regular intervals (recommended: every 50 events or every 10 minutes, whichever comes first), each member computes a signed checkpoint:

```
ConsistencyCheckpoint {
  contextID:    String
  senderDID:    DID
  eventCount:   UInt64           // number of events in local log
  merkleRoot:   [UInt8; 32]      // root hash of local event log
  epoch:        UInt64           // current MLS epoch
  timestamp:    DateTime
  signature:    Ed25519Signature // signed by sender's #active or #agent key (ADR-039); equivocation detection applies to both
}
```

Checkpoints are sent as regular MLS application messages (encrypted, authenticated).

**Checkpoint comparison:** On receiving a checkpoint from another member, each member compares:

- `eventCount`: Must match (within tolerance for in-flight messages). Divergence of more than 5 events indicates inconsistency.
- `merkleRoot`: Must match for the same `eventCount`. Divergence indicates equivocation or log corruption.
- `epoch`: Must match. Divergence indicates a missed MLS Commit (possible suppression).

**Divergence resolution:** If Merkle roots diverge, members exchange event log proofs to identify the first divergent event. This reveals which relay served which version. The context's governance model handles the response.

**Sybil-amplified equivocation defense:** The Relay Consistency Protocol is NOT a majority vote. ANY divergence between ANY two honest members detects equivocation. An attacker who controls Sybil members and a relay can make the Sybil members confirm the attacker's version, but this is irrelevant — two honest members comparing checkpoints will detect the equivocation regardless of how many Sybils agree with the attacker. The defense requires only two honest members in the context.

**Equivocation response protocol.** When equivocation is detected (divergent Merkle roots at the same event count between two honest members), the detecting member initiates the following response:

1. **EquivocationAlert event.** The detector publishes an `EquivocationAlert` as an MLS application message, signed by the detector's Active Signing Key or Agent Signing Key (ADR-039):

```
EquivocationAlert {
  detector_did:         DID
  context_id:           String
  relay_url:            String              // the relay suspected of equivocation
  local_checkpoint:     ConsistencyCheckpoint
  divergent_checkpoint: ConsistencyCheckpoint  // the checkpoint that diverges
  conflicting_hashes:   Vec<[u8; 32]>       // event hashes where logs diverge
  proof:                Vec<MerkleProof>     // inclusion proofs for the conflicting events
  timestamp:            DateTime
  signature:            Ed25519Signature     // signed by detector's #active or #agent key
}
```

The signature covers `context_id || detector_did || relay_url || local_checkpoint.merkleRoot || divergent_checkpoint.merkleRoot || timestamp` using the canonical signed structure format (§9.5.2). The `proof` field includes Merkle inclusion proofs for the conflicting events from both the detector's and the divergent member's logs, enabling independent verification by any group member.

2. **Alert distribution.** The `EquivocationAlert` is distributed to all context members as a standard MLS application message (encrypted, authenticated). Every member's SDK processes the alert independently.

3. **Governance response.** The context's governance engine processes the `EquivocationAlert`. The response is configurable per context via `equivocation_policy` in context parameters:

   - `warn` — Log the alert and notify the application layer. No automated enforcement. Suitable for low-stakes contexts where equivocation may be benign (e.g., relay software bugs).
   - `suspend_relay` (default) — Mark the suspected relay as untrusted in the context's relay set. Members MUST stop publishing to and subscribing from the suspected relay for this context. Members migrate to alternative relays in the context's relay set. If no alternative relays are available, the context enters a degraded state and members are notified.
   - `remove_relay` — Permanently remove the suspected relay from the context's relay set via a governance action (`UpdateRelaySet`). Requires governance authority (admin or vote depending on governance model).

4. **Trust score impact.** The equivocating relay's trust score (§9.3) is reduced. Members who operate relay infrastructure and whose relay is implicated in equivocation receive a `RelayEquivocationViolation` record in the `ViolationStore` (ADR-039). This violation is durable and affects the operator's trust score across all contexts where other members observe the violation record.

5. **Member-initiated equivocation.** If equivocation is attributed to a member (e.g., a member publishes conflicting events to different relays intentionally), the governance engine processes it as a member violation. The configurable response is: `warn` (log only), `suspend_write` (suspend the equivocating member's write access pending admin review — this is the default), or `remove` (remove the member from the context via MLS Remove proposal). Write suspension is implemented by the governance engine adding the member's DID to a `write_suspended` set; the SDK checks this set before accepting application messages from that member and rejects messages from suspended members with an `EquivocationSuspension` error. The suspension is recorded as an `EventType::MemberWriteSuspended { did, reason: "equivocation" }` in the context event log.

### 9.9.4 Selective Suppression of MLS Commits

A specific relay attack: suppress an MLS Remove Commit to keep an excluded member in the group.

**Analysis:** After an MLS Remove Commit is processed, new messages use the new epoch key. The removed member does NOT have this key — they physically cannot decrypt new-epoch messages. Even if the relay suppresses the Commit from being delivered to the removed member, confidentiality is preserved.

**Actual risk:** Suppressing the Commit from OTHER members. Members who don't receive the Commit stay in the old epoch and cannot decrypt new-epoch messages. This is a denial-of-service attack (group state divergence), not a confidentiality breach.

**Mitigation:** MLS Commits are high-priority messages that SHOULD be published to all relays with delivery confirmation. "Delivery confirmation" means relay-level storage ACK — the relay confirms it received and stored the blob. This is NOT recipient-level ACK, which would leak metadata about recipient online status. The actual assurance mechanism is the recovery path: if any member detects they are behind on epochs (they receive a message for epoch N+1 but are on epoch N, or a Relay Consistency Protocol checkpoint (§9.9.3) reveals epoch divergence), they MUST request the missing Commit from other members via directed MLS application messages or from alternative relays in the context's relay set. Multi-relay publication (§9.9.2, recommended: 3 relays) ensures the Commit is available from at least one honest relay even if others suppress it.

## 9.10 Metadata Privacy Architecture

The protocol provides layered metadata privacy protections. Each layer addresses a distinct attack surface:

- **Envelope layer:** Minimal outer envelope with per-context pseudonyms (§9.10.2, §9.10.4)
- **Content layer:** Fixed bucket padding normalizes message sizes (§9.10.3)
- **Connection layer:** Persistent connections + TLS prevent connection-timing correlation (§9.10.5)
- **Traffic layer:** Constant-rate cover traffic masks activity patterns (§9.10.6)
- **Resolution layer:** Local DHT + caching prevents resolution-based tracking (§9.10.7)
- **Query layer:** Pseudonyms + relay partitioning prevent subscription analysis (§9.10.8)
- **Push layer:** Fully opaque push notifications (§10.7)
- **Blocking layer:** AES-256 sender-side keys enable cryptographic blocking without MLS group changes (§9.16)
- **Cross-context key isolation:** Independent MLS key material per context (§9.10.9)
- **Delivery layer:** Relay-side delivery jitter breaks timing correlation between PUBLISH and delivery (§9.10.10)

This section specifies what the protocol protects, how it protects it, and what residual risks remain.

### 9.10.1 What Is Confidential

- Message content (MLS encryption)
- Context-internal state: roles, tools, governance actions, event log content (all encrypted within the MLS group)
- Identity private state (encrypted to owner's key, §3.7)
- UCAN token contents (within encrypted envelopes)
- Sender identity, timestamps, sequence numbers, epoch, generation (all inside encrypted payload)
- Payment data for context-level economics: payment authorizations, receipts, spending UCANs, adapter proofs (all inside encrypted payload, §19.6). Relays never see context-level payment metadata. Relay-level payments (§19.8) are visible to the relay by necessity but not to other parties.

**Broadcast mode confidentiality differences:** In broadcast contexts, the following are NOT confidential (by design): author DID (visible in BroadcastEnvelope), routing_id (publicly derived from context_id via SHA-256), key epoch number. These are acceptable because broadcast authors are public figures and the routing_id must be discoverable for subscribers to subscribe. Message content, subscriber identities (in key request/response exchanges), and block lists remain confidential.

### 9.10.2 Minimal Outer Envelope

The outer envelope — what relays see — contains only:

1. **Routing identifier** — per-context pseudonym (§9.10.4)
2. **Recipient hint** — recipient pseudonym for directed messages, or broadcast marker
3. **Blob TTL** — how long the relay should store before deletion
4. **Encrypted blob** — everything else

Sender identity, timestamps, sequence numbers, epoch, generation — all reside inside the encrypted payload. The relay is a dumb pipe that holds encrypted blobs for a specified duration and delivers them to subscribers of a routing ID. Relay-side ordering, dedup, and expiry are NOT the relay's job. The SDK handles all of this client-side.

**Broadcast mode outer envelope.** Broadcast contexts wrap `BroadcastEnvelope` in the same `OuterEnvelope` format. The `routing_id` is `SHA-256(context_id)` (publicly derivable, unlike encrypted contexts which use HKDF-derived pseudonyms). The `encrypted_blob` contains the serialized `BroadcastEnvelope` — the author DID and metadata are visible after deserialization, but the actual content remains encrypted with the author's broadcast key. The relay sees author identity and envelope metadata but cannot read message content.

### 9.10.3 Fixed Bucket Padding

Pad plaintext to the next bucket boundary before encryption to prevent message size analysis.

**Bucket sizes:** 256B, 1KB, 4KB, 16KB, 64KB, 256KB.

Messages larger than 256KB are chunked. Padding happens below the application layer and above the transport layer — the SDK handles it transparently. Application developers never see it. Relay operators see uniform bucket-sized blobs.

**Chunking protocol.** When a message payload exceeds the largest bucket size (256KB minus the 4-byte length suffix used by bucket padding), the SDK splits it into chunks before encryption:

```
ChunkEnvelope {
  message_id:    [u8; 32]   // SHA-256("SCP-CHUNK-MSG-ID-V1:" || len(payload) || payload || len(sender_did) || sender_did || timestamp_be), unique per logical message
  chunk_index:   u32         // 0-indexed chunk position
  total_chunks:  u32         // total number of chunks in this message
  payload_hash:  [u8; 32]   // SHA-256 of the complete pre-chunked payload
  data:          Vec<u8>     // chunk payload (plaintext fragment)
}
```

_Rationale: `message_id` uses deterministic SHA-256 derivation (32 bytes) rather than random 16-byte generation. Deterministic derivation requires no coordination, enables idempotent retransmission detection, and 32 bytes provides full collision resistance. The `payload_hash` field enables the receiver to verify integrity of the reassembled payload without relying on application-layer checks. Field names (`message_id`, `chunk_index`, `data`) were chosen for clarity over the original (`chunk_id`, `sequence`, `payload`)._

1. **Splitting.** The SDK derives `message_id = SHA-256("SCP-CHUNK-MSG-ID-V1:" || BE32(len(payload)) || payload || BE32(len(sender_did_bytes)) || sender_did_bytes || timestamp_be_bytes)` and `payload_hash = SHA-256(payload)`. The domain separator `"SCP-CHUNK-MSG-ID-V1:"` prevents cross-protocol hash collisions, and the BE32 length prefixes on variable-length fields (`payload`, `sender_did_bytes`) prevent ambiguous concatenation. The plaintext payload is split into fragments of at most `MAX_CHUNK_PAYLOAD_SIZE` bytes (largest bucket size minus 4-byte length suffix = 262,140 bytes). Each fragment is wrapped in a `ChunkEnvelope` with its `chunk_index` and the `total_chunks` count.
2. **Individual encryption.** Each `ChunkEnvelope` is independently encrypted as a separate MLS application message (in encrypted contexts) or a separate sender-key-encrypted message (in broadcast contexts). This means each chunk is individually authenticated (inner signature + MLS membership_tag or sender key AEAD) and individually padded to the nearest bucket boundary (§9.10.3). Individual encryption ensures that a relay cannot correlate chunks by ciphertext similarity — each chunk is an opaque, independently-sized blob.
3. **Transmission.** Chunks are published as separate relay blobs. The relay treats each chunk as an independent message. Chunks MAY be published to different relays in the context's relay set for redundancy.
4. **Reassembly.** The recipient decrypts each chunk individually, then reassembles by `message_id` + `chunk_index` ordering. The recipient maintains a per-`message_id` reassembly buffer. After concatenation, the receiver verifies `SHA-256(reassembled_payload) == payload_hash`; mismatches indicate corruption or tampering and MUST cause the message to be discarded.
5. **Reassembly timeout.** The SDK MUST discard incomplete chunk sets (not all `total_chunks` received) after 60 seconds from receipt of the first chunk in the set. This prevents resource exhaustion from partial chunk deliveries. The timeout is enforced by the SDK session layer that manages reassembly buffers, not by the `ChunkEnvelope` type itself.
6. **Maximum chunks per message.** `MAX_TOTAL_CHUNKS = 262,144`. A single logical message MUST NOT exceed 262,144 chunks, bounding total reassembled message size to approximately 64 GB (`MAX_CHUNK_PAYLOAD_SIZE` * 262,144). _Rationale: the original limit of 256 chunks (64 MB max) was overly restrictive for large file transfers and media streaming. The 262,144 limit allows payloads up to ~64 GB while still bounding reassembly buffer metadata (each buffer entry is a small index + data pointer). For relay-constrained scenarios, relay-advertised `max_blob_size` independently limits per-chunk size._
7. **Maximum chunk payload size.** Each chunk's `data` MUST NOT exceed `MAX_CHUNK_PAYLOAD_SIZE` (262,140 bytes = 256KB minus 4-byte length suffix). This ensures each chunk, after padding, fits in the largest bucket (256KB). If the relay advertises a smaller `max_blob_size` (from `.well-known/scp` relay_config, §10.5.1), the SDK MUST use the smaller limit.
8. **Chunk authentication.** Because each chunk is a separate MLS/sender-key message, chunk forgery and chunk replay are prevented by the same mechanisms as regular messages (§9.8.1, §9.8.2). Additionally, the `payload_hash` field provides end-to-end integrity verification of the reassembled payload — a tampered or injected chunk will cause the hash check to fail at reassembly time.

### 9.10.4 Per-Context Pseudonyms

Each participant derives a per-context keypair that replaces their DID in all outer-envelope fields:

```
context_seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")
context_keypair = Ed25519_keygen(context_seed[0..32])
context_pseudonym = context_keypair.public_key
```

- **Per-DID, not per-VM.** The pseudonym is derived from `identity_key_material` (the DID's `#0` key), so human and agent share one pseudonym per context regardless of which signing key (`#active` or `#agent`) is used for individual messages (ADR-039). This prevents pseudonym divergence from leaking the human/agent distinction to relays.
- **Deterministic:** Same identity + same context = same pseudonym.
- **Unlinkable across contexts:** Different context_id = different pseudonym. Relays cannot correlate activity across contexts.
- **Verification:** Sender includes full DID inside MLS-encrypted payload. Group members verify pseudonym-to-DID mapping on first encounter and cache the association.
- **No ZK proofs** — unnecessary complexity since only group members need to verify the mapping.
- The SDK handles derivation, caching, and verification transparently.
- **HSM compatibility.** Pseudonym derivation is performed via `KeyCustody::derive_pseudonym(identity_key_handle, context_id)` (ADR-006). The HMAC-SHA256 computation happens inside the custody boundary — the private key never leaves the HSM. For hardware-backed keys, the HSM computes the HMAC internally using an associated symmetric key derived during `generate_keypair`. For software keys, the HMAC uses a symmetric pseudonym secret derived during key generation (see below). All implementations produce identical output for the same identity key and context_id, regardless of custody type. See ADR-002 criterion 1 for the full derivation specification.

#### 9.10.4.A Pseudonym Derivation Privacy Model

**Threat: publicly derivable pseudonyms enable membership enumeration.** If `identity_key_material` in the HMAC were the raw Ed25519 public key bytes (which are public by definition), any party knowing a `context_id` and a DID's public key could compute `HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")` and test whether the resulting pseudonym appears as an active subscription on a relay. This constitutes a membership enumeration oracle.

**Mitigation: pseudonym secret.** The `identity_key_material` used in pseudonym derivation MUST be a 32-byte symmetric secret that is NOT publicly derivable. The pseudonym secret is generated alongside the identity keypair and stored within the custody boundary:

```
pseudonym_secret = HKDF-SHA256(
  ikm  = ed25519_private_key_bytes,
  salt = "scp-pseudonym-secret-v1",
  info = "",
  len  = 32
)
```

For **software custody**, the pseudonym secret is derived from the Ed25519 private key bytes during key generation and cached in the `KeyCustody` store. The private key bytes are the only input — the public key is never used.

For **hardware custody** (Secure Enclave, Android Keystore, HSM), where private key bytes cannot be exported, the pseudonym secret is generated as a separate 32-byte random value during `generate_keypair` and stored as an associated symmetric key within the hardware boundary. The hardware computes the HMAC internally using this associated key.

**Cross-platform determinism:** Software implementations derive the pseudonym secret deterministically from the private key, ensuring identical pseudonyms across platforms for the same identity. Hardware implementations use a stored random value — since hardware keys cannot be exported and re-imported, cross-platform identity migration uses the social/device recovery protocol (§3.3), which provisions a new pseudonym secret at the destination.

**Migration from public-key-based derivation:** SDKs that previously used public key bytes MUST re-derive pseudonyms using the pseudonym secret on upgrade. The SDK:
1. Derives the pseudonym secret from the private key (software) or generates one (hardware).
2. Subscribes to both old and new routing IDs for a grace period (2x blob TTL).
3. Announces the new pseudonym to group members via an MLS application message (same mechanism as §9.10.4.1 pseudonym rotation).
4. After the grace period, unsubscribes from the old routing ID.

- **Pre-join context inspection.** Prospective members who know a `context_id` but have not joined the context can retrieve its publicly visible parameters (capability ceiling, governance model, roles, TTL, memory scope — see §5.7) from relays without joining. The relay indexes context metadata under a keyed identifier (see §9.10.4.B below) that does not reveal member identities or message content. It enables the "legibility before opt-in" tenet: any agent evaluating whether to join a context can inspect its parameters by querying the metadata routing ID on the context's relays.

#### 9.10.4.B Metadata Routing ID Privacy

**Threat: publicly derivable metadata routing IDs enable context enumeration.** If `metadata_routing_id = SHA-256(context_id || "scp-metadata")`, any party who knows or guesses a `context_id` can compute the metadata routing ID and probe relays to determine whether the context exists, which relays host it, and (combined with pseudonym enumeration) who is a member.

**Mitigation: keyed metadata routing ID.** The metadata routing ID is derived using a context-specific secret known only to context members and authorized prospective members:

```
metadata_routing_id = HMAC-SHA256(
  key  = context_metadata_key,
  data = context_id || "scp-metadata-v2"
)
```

The `context_metadata_key` is a 32-byte symmetric key distributed as follows:

- **At context creation:** The creator generates `context_metadata_key` and includes it in the context's initial parameters.
- **In invitations:** The `context_metadata_key` is included in the invitation payload (which is encrypted to the invitee's public key). This allows prospective members to inspect context metadata before joining.
- **In contexts with discovery tools:** Public or discoverable contexts publish their `context_metadata_key` in their context entry. This preserves the "legibility before opt-in" property for contexts that want to be found, while keeping non-discoverable contexts invisible to probing.
- **Rotation:** The `context_metadata_key` MAY be rotated via a governance action. On rotation, the context re-publishes metadata under the new routing ID and maintains the old routing ID for a grace period (2x blob TTL).

**Backward compatibility:** Contexts created before this change use the legacy `SHA-256(context_id || "scp-metadata")` derivation. SDKs MUST support both derivation schemes during the migration period. New contexts MUST use the keyed derivation.

#### 9.10.4.1 Pseudonym Rotation (BLACK-001 Mitigation)

To mitigate long-term pseudonym-level traffic analysis by a compromised relay (BLACK-001), pseudonyms support epoch-based rotation. The v2 derivation includes a rotation epoch:

```
context_seed_v2 = HMAC-SHA256(identity_key_material, context_id || epoch_BE || "scp-pseudonym-v2")
context_keypair_v2 = Ed25519_keygen(context_seed_v2[0..32])
```

where `epoch_BE` is a 64-bit big-endian pseudonym rotation epoch (distinct from MLS epochs).

- **Domain separation:** The v2 domain separator `"scp-pseudonym-v2"` differs from v1's `"scp-pseudonym"`, so v2 epoch 0 produces a different pseudonym than v1. This prevents accidental domain confusion.
- **Rotation trigger:** Context governance policy determines rotation frequency (e.g., daily, weekly, on membership change). The SDK manages rotation timing.
- **Transition protocol:** During rotation, the client subscribes to BOTH the old and new `routing_id` for a grace period (recommended: 2x the context's blob TTL) to avoid missing messages from peers who have not yet learned the new pseudonym. The sender announces the new `routing_id` to group members via an MLS application message containing `{ pseudonym_epoch: N, routing_id: <new_routing_id> }`.
- **Backward compatibility:** Contexts that do not opt into rotation continue using v1 derivation with static pseudonyms. The existing mitigations (cover traffic, padding, relay partitioning) provide substantial protection for these contexts.
- **HSM compatibility:** Same as v1 — `KeyCustody::derive_rotatable_pseudonym(identity_key_handle, context_id, pseudonym_epoch)` delegates the HMAC to the custody boundary.

### 9.10.5 Connection Privacy

1. **Persistent connections mandatory on desktop/workstation/server.** Constant connection to each relay regardless of activity. Prevents connection-timing correlation.
2. **Mobile: push-wake + burst.** Opaque push wakes device, SDK connects to relays, exchanges messages, disconnects.
3. **TLS 1.3 required for all relay connections** (§9.13). Relay operators see the client's IP address — the same information any web server sees. Combined with per-context pseudonyms (§9.10.4), the relay cannot link the IP to a specific identity or correlate activity across contexts.
4. **No custom mix network, no custom proxy protocol.** The protocol does not mandate IP-layer anonymization. The privacy posture already exceeds any conventional app: relays see only pseudonyms, bucketed blob sizes, and TTLs. Clients concerned about IP-level privacy can route through a VPN or Tor at the transport layer — this is a client configuration choice, not a protocol requirement.

### 9.10.6 Cover Traffic

Cover traffic uses **tiered configuration driven by transport profiles** (§10.13). The SDK selects a cover traffic tier based on the active transport profile. Disabling cover traffic (tier `off`) degrades traffic analysis resistance but has no functional impact on message delivery or protocol correctness.

**Cover traffic tiers:**

| Tier | Interval | Padding size | Use case |
|------|----------|-------------|----------|
| `full` | 30s | 1024 bytes | Desktop/server profiles — maximum metadata privacy |
| `reduced` | 120s | 256 bytes | Mobile profile — battery-conscious |
| `off` | — | — | Constrained profile (§10.16), push-wake connections |
| `custom` | User-specified | User-specified | Advanced configuration via `CoverTrafficTier::Custom { interval, message_size }` |

**Configuration.** `CoverTrafficConfig` uses `tier: CoverTrafficTier` to select the active tier. The tier determines the interval and padding size. `CoverTrafficTier::from_profile(profile)` maps each `TransportProfile` to its default tier: `Server` and `Desktop` → `full`, `Mobile` → `reduced`, `Constrained` → `off`.

**Invariants (apply to all tiers except `off`):**

1. **Constant-rate.** Dummy messages are always sent at each interval tick. Real messages are sent as additional traffic — they never suppress a dummy. This prevents timing oracles where observers infer real traffic from missing dummies.
2. **Push-wake connections: no cover traffic.** Push-wake connections are transient and brief; cover traffic is meaningless over them.
3. **Dummy message format.** Single-byte flag inside encrypted payload distinguishes real from dummy. `REAL_FLAG = 0x01`, `DUMMY_FLAG = 0x00`. Recipients decrypt, check the flag, discard dummies.
4. **Rate is per relay connection, not per context.** Prevents relay from correlating traffic rate changes with context activity.
5. **Bucket padding.** All payloads (real and dummy) are padded to the nearest bucket boundary per §9.10.3. This normalizes message sizes regardless of content length.

**Bandwidth baseline by tier:**
- `full`: ~15MB/day for 5 relay connections at 1024-byte padding. Real messages add <5% above baseline at moderate usage.
- `reduced`: ~1.8MB/day for 5 relay connections at 256-byte padding. Suitable for metered mobile connections.
- `off`: Zero cover traffic overhead. Constrained devices (§10.16) typically operate behind a gateway agent that provides cover traffic on their behalf.

**Bandwidth budget.** An optional bytes-per-minute cap across all connections limits total cover traffic bandwidth. When the budget is reached, the tier degrades gracefully: `full` → `reduced` → `off`. The budget is a soft limit for resource-constrained environments, not a security feature.

### 9.10.7 DID Resolution Privacy

1. **Desktop/workstation/server: local Mainline DHT node, mandatory.** DID resolution queries become indistinguishable from DHT routing traffic. The device participates as a full DHT node, routing queries for others as well as itself.
2. **Mobile: DHT queries via standard HTTPS gateway or lightweight DHT client.** Resolution is infrequent (once per first contact, then cached), so latency is acceptable.
3. **Aggressive caching:** 24-hour refresh for active contacts, 7-day for inactive. Stale documents detected via BEP44 sequence number comparison. Key change alerts trigger immediate re-resolution.
4. **No batch/prefetch, no resolution proxy.** Local DHT node on desktop and caching on mobile provide practical privacy without new infrastructure.
5. **Relay-based resolution adds one observer.** When DID documents are also resolved from SCP relays (§3.10.2), the relay operator learns that a resolver IP queried a specific `routing_id` — and can infer which DID if the relay stores that DID's document (§3.10.9). This is no privacy degradation vs. DHT-only: the relay operator already sees message traffic metadata (§9.9.1). Parallel dual-layer resolution (§3.10.4) means no single backend is the exclusive observer.

### 9.10.8 Relay Query Privacy

1. **Per-context pseudonyms (§9.10.4) are the foundation.** Relay cannot link subscriptions across contexts.
2. **Relay set partitioning, mandatory.** Each context SHOULD use different relays from the client's other contexts. SDK distributes contexts across relays to minimize overlap.

**Combined effect:** Relay sees pseudonyms (unlinkable to identity) on a relay hosting only a fraction of the client's total context set. Per-context pseudonyms prevent cross-context linkage; relay partitioning limits the fraction of a client's activity visible to any single relay.

**Rejected alternatives:** Subscription mixing (subscribing to decoy routing IDs alongside real ones) was considered and rejected — decoy routing IDs receive zero traffic, making them trivially distinguishable from real subscriptions. Private Information Retrieval (PIR) was considered and rejected — computational overhead is disproportionate to the privacy gain given that pseudonyms and partitioning already prevent the relay from linking subscriptions to identities or contexts.

### 9.10.9 Cross-Context Key Isolation

Each SCP context is a separate MLS group with independent key material. Compromising one context's keys reveals nothing about any other context's keys. The identity key (Ed25519) is shared across contexts but signs actions — it never directly encrypts group content. MLS handles group encryption with ephemeral key material derived independently per group. Per-context pseudonyms (§9.10.4) prevent the identity key from being visible outside encrypted payloads.

### 9.10.10 Relay Delivery Jitter (BLACK-001 Mitigation)

Relays add a uniformly random delay in `[0, delivery_jitter_ms)` (default: 50ms) before forwarding each stored blob to its subscribers. This breaks the timing correlation between PUBLISH arrival and subscriber delivery, making it harder for a compromised relay to infer communication patterns between specific pseudonyms.

1. **Per-subscriber jitter.** The delay is applied independently for each subscriber of a `routing_id`, so even subscribers on the same routing ID receive blobs at slightly different times. This prevents a relay from using delivery ordering as a correlation signal.
2. **Configurable.** Relay operators can tune the jitter range via `RelayConfig::delivery_jitter_ms`. Higher values provide stronger timing decorrelation at the cost of delivery latency. Set to 0 to disable (useful for low-latency deployments that accept the residual risk).
3. **Complements cover traffic.** Delivery jitter addresses the relay-to-subscriber path. Cover traffic (§9.10.6) addresses the client-to-relay path. Together they reduce timing correlation on both legs of the relay.

### 9.10.11 Residual Risks

Even with all protections in this section, the following metadata leaks remain:

- **IP visibility:** Relay operators see the client's IP address (same as any web service). Per-context pseudonyms prevent linking IPs to identities, but a relay operator with access to IP logs could correlate connection patterns. Clients requiring IP anonymity can use a VPN or Tor at the transport layer.
- **Cover traffic volume analysis:** The additive model eliminates timing oracles (missing dummies never reveal real traffic) but introduces a volume oracle: burst activity above the dummy baseline is visible as elevated traffic to a network observer. At moderate usage the increase is <5% above baseline, but sustained high-volume periods are distinguishable from idle. Sophisticated statistical analysis may further distinguish real message patterns within the traffic stream.
- **Push notification timing:** Apple/Google learn that a device received a notification at a specific time. Content and source remain opaque (§10.7).
- **DHT participation patterns:** On desktop, DHT routing traffic is mixed with resolution queries, but a network observer can see DHT participation.
- **Relay trust:** Relays see blob sizes (bucketed), TTLs, and pseudonyms. A relay colluding with a context member could correlate pseudonyms to identities for that context only.

## 9.11 Key Continuity Verification

Equivalent to Signal's "safety numbers." Allows two parties to verify they have the correct keys for each other, detecting MITM on DID resolution.

**Fingerprint format:**

```
fingerprint = SHA256("SCP-KEY-CONTINUITY-V1:" || len(did_a) || did_a || len(did_b) || did_b || a_identity_key || a_active_key || a_agent_key || b_identity_key || b_active_key || b_agent_key)
```

Where `did_a, did_b` are the two DID strings ordered by lexicographic sort, `len()` is a 4-byte big-endian length prefix (prevents concatenation ambiguity when DID strings have variable length), and keys are raw 32-byte Ed25519 public keys concatenated in the order shown (identity, active, agent) within each DID's block.

All three verification methods (`#0`, `#active`, `#agent`) from each party's DID document are included to detect substitution of any single key (ADR-039). If a DID has no `#agent` verification method (no agent bound), a domain-derived sentinel `SHA-256("SCP-ABSENT-AGENT-KEY")` (truncated to 32 bytes) is used instead. This avoids collision with the Ed25519 identity point (all zeros) and provides domain separation from legitimate key values. The `"SCP-KEY-CONTINUITY-V1:"` domain separator prevents cross-protocol signature confusion.

Displayed as:
- A 12-word mnemonic (BIP-39 word list, first 128 bits of the hash)
- A 60-digit decimal number (first 200 bits)
- A QR code encoding the full 256-bit hash

**Verification flow:**

1. Alice and Bob each compute the fingerprint using their local knowledge of the other's public key.
2. They compare fingerprints via an out-of-band channel (in person, voice call, trusted messaging app).
3. If fingerprints match, key continuity is verified. The SDK records this verification event in identity private state (§3.7).
4. If fingerprints do not match, a MITM is actively intercepting DID resolution. The SDK MUST alert with maximum severity.

**Key change detection:**

- The SDK records the public key associated with each DID on first encounter (Trust On First Use / TOFU).
- On any subsequent DID resolution that returns a different public key, the SDK MUST: (a) alert the user that the key has changed, (b) invalidate the previous key continuity verification, (c) refuse to send encrypted content to the new key until the user explicitly accepts the change or completes re-verification.
- Legitimate key changes (rotation, recovery) are distinguishable: for did:dht, the new DID document is signed by the old key (authorization chain). For social recovery, trusted contacts independently confirm the rotation.

## 9.12 Compromise Recovery Protocol

When a key is known or suspected to be compromised, the following ordered steps constitute the recovery protocol:

**1. Key rotation on trusted device.**
- **Agent Signing Key compromise (most common case):** The agent runtime is typically less secure than device HSM, making `#agent` the most likely key to be compromised. Recovery: (1) Human uses `#0` (Identity Key) to publish a new DID document removing or replacing the `#agent` verification method. (2) Revoke all UCANs with `fct.scp_key_scope: "#agent"` — add to per-context `RevocationList` and distribute via MLS application messages. (3) Issue MLS Update proposals in all active contexts with new credentials (updated `signing_key_id`). (4) Publish new KeyPackages. The human's `#active` key, root UCANs, and Identity Key are unaffected — only agent-scoped material is rotated (ADR-039). This is the cheapest recovery scenario: no identity migration, no root UCAN reissuance.
- **Active Signing Key compromise (common case):** Call `rotate_active_key` (ADR-003 §4a). Generate new active signing keypair, update DID document signed by Identity Key, publish to DHT. The DID string does NOT change. No identity migration needed.
- **Identity Key compromise (rare, severe):** Call `migrate_identity` (ADR-003 §4b) using the pre-rotation key from cold storage. The pre-rotation commitment in the old DID document proves the legitimate owner is rotating, not the attacker. Creates a new DID. Old DID document updated with forwarding record. `DidRotationEvent` sent to all contexts with pre-rotation proof.
- **Both keys compromised, pre-rotation key available:** Same as Identity Key compromise — the pre-rotation key resolves the race condition.
- **All keys compromised:** Social recovery via trusted contacts with admin roles removing and re-adding the member under a new identity.

**2. MLS Update in all active contexts.** Issue MLS Update proposals in every context. This provides post-compromise security: new epoch keys are derived from the new key material, making the compromised old key useless for future messages. If the old key is unavailable (device stolen), a trusted co-member with admin role must remove and re-add the member.

**3. UCAN revocation.** Revoke all UCAN tokens issued by the compromised key. Add revocations to each context's `RevocationList` and distribute via MLS application messages (§9.5). Issue new tokens signed by the new key.

**4. KeyPackage rotation.** Delete all outstanding KeyPackages associated with the old key from relays. Publish new KeyPackages signed by the new key.

**5. Contact notification.** The SDK sends a key-change notification to all known contacts. Contacts who completed Key Continuity Verification (§9.11) are alerted that re-verification is needed.

**6. Identity private state re-encryption.** Re-encrypt identity private state (§3.7) under the new key. Publish re-encrypted state to relays.

**Step ordering and failure isolation:** Steps 1-6 are ordered by dependency: key rotation (1) must complete before MLS Updates (2) because Updates use the new key material; MLS Updates (2) must complete before UCAN revocation/reissuance (3) because new UCAN tokens are signed by the new key; KeyPackage rotation (4) must follow to prevent new group additions using old key material; steps 5 and 6 are cleanup and can execute in any order after step 4. Steps 2-4 are per-context — failure in one context does not block recovery in other contexts. The SDK retries failed contexts independently. A context where MLS Update cannot succeed (e.g., member has been offline too long and requires Tier 3 re-join per ADR-029) is flagged for manual re-join and does not block recovery in other contexts.

**Time-shifted key compromise:** An attacker who extracts MLS state at time T can read messages until the next PCS Update. Forward secrecy protects all messages from before T (old epoch keys already deleted). PCS protects all messages after the next Update. The vulnerability window is bounded by the PCS Update interval (§9.7.3).

## 9.13 Transport Security Requirements

**Relay connections MUST use TLS 1.3** (or higher). TLS 1.2 is acceptable only as a fallback when TLS 1.3 is unavailable.

**Certificate validation:** Standard WebPKI validation. The SDK MUST reject self-signed certificates for relay connections unless the user has explicitly configured a self-hosted relay with a pinned certificate.

**Certificate pinning:** The SDK SHOULD support certificate pinning for known relays. If did:web is used as a fallback, certificate pinning for the resolution server is mandatory.

**Relay authentication:** SCP does not depend on relay authentication — encryption-as-access-control (§10.5) makes it unnecessary for confidentiality. Individual transport adapters may support adapter-specific authentication mechanisms (e.g., NIP-42 for Nostr relays). Relay authentication may be useful for relays that want to limit their user base or implement per-user rate limiting.

**Direct connections:** For the direct WebSocket transport adapter, connections between devices MUST use TLS (wss://) unless both devices are on the same local network AND the user has explicitly accepted the risk.

**Self-hosted relay exception:** `ws://` (plaintext WebSocket) is permitted for self-hosted relays discovered via DHT-resolved DID documents (§10.12.6). These relays have no domain and cannot obtain CA-signed certificates. MLS provides the confidentiality boundary; TLS on a dumb pipe protects already-encrypted traffic. The SDK MUST reject `ws://` relay URLs obtained from `.well-known/scp` or any non-DHT source.

## 9.14 Clock and Ordering Model

**Clock model:** SCP does not require synchronized clocks. Timestamps are best-effort, used for ordering hints and replay detection, not for security-critical decisions.

**Clock skew tolerance:** 5 minutes. Messages with timestamps more than 5 minutes in the future are rejected. This is generous enough to handle devices with poorly-set clocks while tight enough to limit replay windows.

**Authoritative ordering:** The Merkle event log order is authoritative. Timestamps inform real-time ordering in the SDK. Once events are committed to the log, the log order is the permanent record.

**Causal ordering:** MLS epoch boundaries serve as synchronization points. Within an epoch, sender generation numbers provide per-sender total ordering. Cross-sender ordering within an epoch relies on timestamps (best-effort) and the Merkle log (authoritative after the fact).

## 9.15 Ephemeral Key Destruction Verification

**Honest limitation:** Proving that a key has been destroyed on a remote device is impossible in the general case. A compromised device can claim destruction while retaining the key. This mechanism provides the strongest verifiable guarantees the hardware supports.

**Platform-attested destruction:** On platforms with hardware security (Secure Enclave, Android Keystore), the SDK requests a destruction attestation from the hardware after deleting key material.

**Destruction protocol for ephemeral context close:**

1. Context TTL expires or participants trigger close.
2. Each member destroys their MLS group state locally: tree secrets, all epoch key schedules, application key material.
3. Each member generates a destruction attestation:

```
KeyDestructionAttestation {
  contextID:             String
  memberDID:             DID
  destroyedAt:           DateTime
  platformAttestation:   PlatformAttestation?  // hardware-backed if available
  method:                .hardwareBacked | .softwareOnly
  signature:             Ed25519Signature       // signed by #0 (Identity Key) or #active (Active Signing Key); NOT #agent — agents cannot sign destruction attestations (ADR-039)
}
```

4. Attestations are published to relays (outside the now-destroyed context). They are signed by the identity key so they remain verifiable after context keys are destroyed.

**Trust levels for destruction claims:**

- **Hardware-attested** (Secure Enclave / Keystore attestation): High confidence. The hardware claims the key is gone.
- **Software-only** (`memset(0)` on key material in memory): Moderate confidence. Memory dumps, swap files, or crash logs may have retained the key.
- **No attestation** (member went offline before close): No confidence. The member may still have the key.

The protocol provides the strongest guarantees the hardware supports and is explicit about where those guarantees end. This is consistent with the honest limitations acknowledged in §5.11.

## 9.16 Sender-Side Key Layer (Blocking)

The MLS group key provides confidentiality against outsiders but not against other group members. Blocking a participant within a context requires a cryptographic layer below MLS that allows selective readability.

### 9.16.1 Key Architecture

Each participant in a context holds one AES-256 symmetric sender key. All messages are encrypted with the sender's key before being encrypted with MLS. Blocked parties can decrypt the MLS layer but receive opaque ciphertext from the blocking party.

- **Key type:** AES-256-GCM symmetric. One key per sender per context.
- **Key size:** 32 bytes per sender key per context member. Storage is trivial.
- **Encryption order:** Sender-first (AES-256-GCM), then MLS. Recipients decrypt MLS layer, then decrypt sender layer with the cached sender key.

**Sender-key plaintext wire format.** The MLS application message plaintext for application messages is structured as:

```
epoch (8 bytes BE) || sequence (8 bytes BE) || sender_key_ciphertext
```

Where `epoch` is the sender's current `sender_key_epoch` and `sequence` is a per-sender monotonic send counter (incremented after each successful encryption). The epoch and sequence are bound into the AES-256-GCM AAD (§9.16.1 AAD format below) alongside `context_id` and `sender_did`, preventing ciphertext relocation across epochs, reordering within an epoch, and cross-sender attribution forgery. The 16-byte header is inside the MLS ciphertext envelope and therefore protected by MLS confidentiality and integrity.

**Sender-key AAD format.** The AAD for sender-key AES-256-GCM encryption is:

```
BE32(len(context_id)) || context_id || BE32(len(sender_did)) || sender_did || epoch (8 bytes BE) || sequence (8 bytes BE)
```

Variable-length fields use 4-byte big-endian length prefixes to prevent boundary-shift collisions (§9.5.1). Recipients reconstruct the AAD from the 16-byte header and MLS credential, then verify it during AEAD decryption.

**Receive-side replay detection.** Recipients MUST maintain a per-sender `(last_epoch, last_sequence)` tracker. Messages with `epoch < last_epoch` or `(epoch == last_epoch && sequence <= last_sequence)` MUST be rejected as replays. This provides defense-in-depth alongside MLS-layer replay protection. The tracker is persisted in the crypto state snapshot.

**Epoch poisoning defense.** Recipients MUST reject sender key distributions with `epoch > current_epoch + 1000`. This prevents an attacker from setting an artificially high epoch (e.g., `u64::MAX`) to permanently block future legitimate key rotations via the epoch monotonicity check.

**Management messages.** MLS application messages may carry management payloads (e.g., sender key distributions during key rotation) instead of application content. Management messages are distinguished by a 4-byte ASCII magic prefix:

```
SCPM_MAGIC = [0x53, 0x43, 0x50, 0x4D]  ("SCPM" — Shared Context Protocol Management)
```

Management message MLS plaintext format: `SCPM_MAGIC (4 bytes) || management_payload`. Management messages bypass the sender-key encryption layer entirely — they are MLS-encrypted only, with authentication provided by MLS group membership. Recipients check the first 4 bytes of the MLS plaintext after decryption: if they match `SCPM_MAGIC`, the message is routed to management message processing; otherwise, it is parsed as a sender-key-encrypted application message (16-byte header + ciphertext). The epoch value in an application message header starts at 1 and increments monotonically, so the first 4 bytes (`0x00000000` for epoch ≤ 255) can never collide with `SCPM_MAGIC` (`0x5343504D`). Management payloads MUST NOT exceed 65,536 bytes (64 KiB).

**Management prefix exclusivity.** The `SCPM_MAGIC` check MUST occur **exactly once** per incoming message, at the MLS plaintext → application message boundary described above. No other layer — transport, relay, outer-envelope processing, sender-key decryption, or any post-dispatch application code — is permitted to strip, test, or otherwise depend on the magic prefix. Implementations MUST centralize this check to a single call site to preserve the single-responsibility invariant that motivates the framing: message type is a property of MLS plaintext, not of any other layer. Conformance implementations MAY share the check between a production crypto provider and a test-equivalent provider, provided both invoke the same canonical helper. Duplicating the check elsewhere in the pipeline is a protocol violation.

**Wrapping key terminology.** The sender-side key layer uses two distinct wrapping keys, both HPKE-based (RFC 9180 Base mode, §9.5) but serving different roles: (1) the **stable wrapping keypair** (below) protects the persistent per-sender AES-256 symmetric key during key distribution — it is long-lived and published in the MLS LeafNode; (2) the **ephemeral wrapping keypair** (§9.16.2) protects per-request key material during individual key exchanges — it is generated fresh for each `SenderKeyRequest` and discarded after use. Both use X25519 DHKEM + HPKE for key encapsulation, but the stable key enables offline key distribution while the ephemeral key provides forward secrecy for individual key exchanges.

**Stable wrapping keypair.** Each member maintains a single dedicated X25519 keypair per context (one per DID, shared by human and agent — ADR-039), used exclusively for HPKE wrapping of sender key distributions (§9.16.2). This keypair is published as an MLS LeafNode extension (`scp_wrapping_key`) and is distinct from the MLS leaf HPKE key used for MLS key agreement. The wrapping keypair does NOT rotate on MLS Updates (epoch advances) — it remains stable across epochs so that sender key distributions can always be unwrapped, even by members who are offline during epoch transitions or who join after an epoch advance. The wrapping keypair rotates only on: (1) identity key rotation (§9.12), or (2) suspected compromise. On rotation, the member publishes the new wrapping public key in their LeafNode extension via an MLS Update and re-distributes their current sender key to all non-blocked members using the new wrapping keys.

### 9.16.2 Key Distribution (Pull-Based)

Sender keys are distributed via a pull-based request/response protocol. When a sender generates or rotates a key, they publish a lightweight epoch advance notification as an MLS application message. Members request the actual key material on demand via directed MLS application messages. This replaces a push-based model where the sender would HPKE-encrypt the key to every recipient in a single message — the pull model reduces block cost from O(N) to O(1) on the sender side and naturally load-balances key distribution.

**Protocol flow:**

1. **Epoch advance notification.** When a sender generates or rotates their key, they publish a `SenderKeyEpochAdvance { sender_did, epoch, signature }` as an MLS application message. The signature covers `context_id || sender_did || "key_epoch" || epoch`, signed by the sender's Active Signing Key or Agent Signing Key (ADR-039). This is **O(1)** regardless of group size.

2. **Key request.** Members who need the key (because they see a new epoch, or because they just joined) send a `SenderKeyRequest { requester_did, sender_did, epoch, wrapping_pubkey, signature }` as an MLS application message with `recipient_hint` directed to the key holder. The `wrapping_pubkey` is a fresh ephemeral X25519 key generated per request.

3. **Key response.** The key holder's SDK processes the request: verifies the signature, checks the block list. If the requester is not blocked, responds with `SenderKeyResponse { sender_did, epoch, hpke_sealed_key, ephemeral_pubkey, request_nonce }` via an MLS application message with `recipient_hint` to the requester. The sender key is sealed using HPKE Base mode (RFC 9180) to the requester's ephemeral wrapping public key. If blocked, no response — the blocked party cannot obtain the key. The `ephemeral_pubkey` field carries the HPKE encapsulated key (`enc` in RFC 9180 terminology) and `hpke_sealed_key` carries the AEAD ciphertext (`ct`).

**HPKE Base mode specification (RFC 9180).** Sender key distribution uses HPKE Base mode (`mode_base`, §5.1.1 of RFC 9180) with the following suite:

- **KEM:** DHKEM(X25519, HKDF-SHA256) — KEM ID `0x0020` (RFC 9180 §7.1)
- **KDF:** HKDF-SHA256 — KDF ID `0x0001` (RFC 9180 §7.2)
- **AEAD:** AES-128-GCM — AEAD ID `0x0001` (RFC 9180 §7.3)

This suite matches the MLS ciphersuite (§9.5) and the DID-to-DID HPKE suite, minimizing the cryptographic surface area.

**Seal (sender-side):**

1. Call `SetupBaseS(requester_wrapping_pubkey, info)` (RFC 9180 §5.1.1) to obtain `(enc, sender_context)`.
2. Call `sender_context.Seal(aad, sender_key_bytes)` to obtain `ct`.
3. Transmit `enc` as `ephemeral_pubkey` (32 bytes) and `ct` as `hpke_sealed_key` (32 + 16 = 48 bytes, ciphertext + AEAD tag) in the `SenderKeyResponse`.

**Open (recipient-side):**

1. Call `SetupBaseR(enc, wrapping_secret_key, info)` (RFC 9180 §5.1.1) to obtain `recipient_context`, where `enc` is the `ephemeral_pubkey` from the response. The wrapping secret key is computed inside the `KeyCustody` boundary via `dh_agree(wrapping_key_handle, enc)`.
2. Call `recipient_context.Open(aad, ct)` to recover `sender_key_bytes`, where `ct` is the `hpke_sealed_key` from the response.

**`info` parameter (domain separation):**

```
info = "scp-sender-key-v1" || BE32(len(context_id)) || context_id || BE32(len(sender_did)) || sender_did || epoch_bytes
```

Where `context_id` and `sender_did` are UTF-8 bytes with 4-byte big-endian length prefixes (preventing boundary-shift collisions per §9.5.1) and `epoch_bytes` is the 8-byte big-endian encoding of the sender key epoch. The `info` string binds the HPKE encryption to a specific context, sender, and epoch. Using a different `info` on open produces a different derived key, causing AEAD decryption to fail.

**`aad` parameter (additional authenticated data):**

```
aad = BE32(len(context_id)) || context_id || BE32(len(sender_did)) || sender_did || epoch_bytes
```

Where fields use the same encoding as `info` (with `BE32(len())` length prefixes, without the domain separator prefix). The AAD binds the ciphertext to the context and sender, preventing cross-context and cross-sender key substitution attacks. Tampering with any field in the wire format causes AEAD verification to fail.

**Nonce:** The AEAD nonce is managed internally by the HPKE context (RFC 9180 §5.2 `ComputeNonce`). Implementations MUST NOT generate or supply an external nonce — HPKE derives it from the key schedule. Since each `SenderKeyResponse` creates a fresh HPKE context (fresh ephemeral keypair), the internal sequence counter starts at 0 and only one `Seal`/`Open` call is made per context.

**New member join (pull-based):** When a new member joins the group, they observe each existing member's current sender key epoch from the group state. The new member publishes a `SenderKeyRequest` for each member whose key they need. Each member's SDK responds automatically (checking block list). Same O(N) total work as a push model, but demand-driven and naturally load-balanced.

**Grace period.** When an epoch advances, the sender SHOULD continue accepting the old key for decryption of in-flight messages for 30 seconds (same grace window as MLS epoch keys, §9.7.2, ADR-001 criterion 6). Messages encrypted with the new key and old key coexist briefly.

**Normal operation:** Sender keys do not rotate on MLS epoch advances. This is intentional: old sender keys are retained for historical message decryption. Blocking is about future messages, not retroactive access.

### 9.16.3 Block Protocol

When Alice blocks Bob:

1. Alice persists the block to her block list (identity private state, §3.7.1 for global blocks; context state for in-context blocks) BEFORE any key operations. **This ordering is mandatory** — the block list must be authoritative before `SenderKeyEpochAdvance` publication. Without this ordering invariant, Bob can race to send a `SenderKeyRequest` for the new key before the block list is updated, defeating the block.
2. Alice generates a new AES-256-GCM sender key and increments her `sender_key_epoch`.
3. Alice publishes `SenderKeyEpochAdvance { sender_did: alice_did, epoch: N, signature }` as an MLS application message. **O(1) cost** — no per-recipient HPKE payloads. All group members see the epoch advance.
4. Alice sends a **signed** block notification to Bob as an MLS application message: `{"type": "block", "blocker": "did:dht:alice", "blocked": "did:dht:bob", "signing_key_id": "#active", "timestamp": unix_ms, "signature": "<Ed25519>"}`. The signature covers the canonical hash `SHA-256("SCP-BLOCK-NOTIFICATION-V1:" || len(context_id) || context_id || len(blocker_did) || blocker_did || len(blocked_did) || blocked_did || len(signing_key_id) || signing_key_id || timestamp_BE)` — see the BlockNotification row in §9.5.2 for field order and encoding. `alice_signing_key` is Alice's `#active` (Active Signing Key) or `#agent` (Agent Signing Key) — either is valid (ADR-039); the `signing_key_id` field tells the verifier which DID document verification method to resolve. The signature prevents forgery — without it, any group member could impersonate Alice and trick Bob into rotating his sender key. MLS application messages prove group membership but not individual sender identity within the message payload.
5. Non-blocked members observe the epoch advance and send `SenderKeyRequest` for Alice's new key (§9.16.2). Alice's SDK checks the block list for each request — responds with the HPKE-encrypted key for non-blocked members, ignores requests from Bob. **O(1) per response.** For global blocks (Tier 2), Alice's SDK checks the identity-level block list directly — not only the per-context block list — to prevent bypass via context-level propagation delays.
6. Bob's client **verifies the block notification signature** by resolving the public key identified by the notification's `signing_key_id` from Alice's DID document (`#active` or `#agent` — ADR-039). If verification fails, the notification is discarded and logged for anomaly detection. If verification succeeds, Bob's client automatically rotates Bob's sender key (incrementing his own epoch), publishes his own `SenderKeyEpochAdvance`, and adds Alice to Bob's block list. When members request Bob's new key, Bob's SDK responds to everyone except Alice.
7. The block event is recorded in the context event log with `EventType::MemberBlocked { blocker, blocked, signature }` for auditability.

**Block event observability:** Block events are observable to the group. The epoch advance notifications are visible to all members, and the block notification is an MLS application message. Other members can infer the block. This is an acceptable tradeoff, consistent with how other messaging systems handle blocks. The protocol prioritizes cryptographic enforcement of the block over concealing the block event.

**Result:** Both Alice and Bob have new sender keys that exclude each other. Neither can read the other's future messages. Other context members request and receive both new keys. The block completes with O(1) sender cost (epoch advance + block notification), with key distribution costs naturally spread across individual member requests.

### 9.16.4 Blocking vs. Removal

Blocking and removal are distinct operations with different mechanisms:

- **Blocking** (§9.16): Sender-side key rotation. The blocked party remains in the MLS group. They can see encrypted blobs from the blocker but cannot decrypt them. They retain access to messages from non-blocking members. Blocking is a per-relationship decision, not a group decision.
- **Removal** (§9.7): MLS group epoch advance excluding the removed member. The removed party loses access to all future messages in the context. Removal requires governance authority (admin role or context rules). Removal implies blocking but blocking does not imply removal.

### 9.16.5 Forward Secrecy Interaction

Sender keys rotate ONLY on block events, not on MLS epoch advances. This is a deliberate design choice:

- MLS provides forward secrecy for group-level encryption via epoch advancement.
- Sender keys provide selective readability within the group.
- Rotating sender keys on every epoch would require O(N) individual key requests per epoch advance — prohibitive for active contexts.
- Old sender keys are retained for historical message decryption. A member who joins and receives the current sender keys can decrypt all messages encrypted with those keys (forward and backward within the sender key's lifetime). Historical access boundaries are defined by block events and member joins, not by time.

**Sender key epoch counter.** Each sender maintains a monotonic `sender_key_epoch` counter (starting at 0 on key generation, incremented on each rotation). The epoch counter is included in `SenderKeyEpochAdvance` notifications and `SenderKeyRequest`/`SenderKeyResponse` messages. This enables members to detect missed rotations (gap in observed epochs), detect stale keys (epoch lower than expected), and correctly associate cached keys with the epoch they belong to. The `KeyEpochAdvance` event type (ADR-011) records epoch advances in the context event log for auditability.

### 9.16.6 Sybil Resistance at the Blocking Layer

The block list (§9.16.3) is per-DID. A Sybil attacker — one human controlling multiple DIDs — can create a fresh DID not on the block list and use it to request the new sender key after a block event. Under the shared-DID model (ADR-039), the agent key lives inside the human's DID document — creating a separate agent identity requires creating a full human-grade DID with its own identity depth (attestations, history, economic activity). This mechanically enforces the "every agent traces to a human" tenet: the agent IS the human's DID. The Sybil cost for agents is identical to the Sybil cost for humans. Despite this mechanical enforcement, the block list alone does not prevent all bypass. This section specifies the mitigations.

**Mitigation 1: Membership gate.** `handle_sender_key_request` MUST verify that the requester's DID is a current member of the context before distributing sender keys. In Encrypted contexts, MLS group membership already gates who can observe application messages (including `SenderKeyRequest`), so this is defense-in-depth redundancy. In Broadcast contexts, where key requests travel as relay messages outside MLS, the membership gate is the primary defense: a Sybil DID that has not been admitted through normal subscription controls (DID-authentication for open contexts, UCAN validation for gated contexts) cannot request keys. The Sybil attacker must first pass the context's admission controls — earned capacity thresholds, UCAN gating, device attestation requirements, or whatever the context mandates — before they can even attempt a key request. This raises the cost of Sybil bypass from "create a DID" to "create a DID AND satisfy context admission requirements."

**Mitigation 2: Identity-linked block expansion.** When blocking a DID, the blocker's SDK SHOULD expand the block list to include all DIDs known to be linked to the same identity. Identity linkage sources include:

- **Attestation chains** (§3.5, §7.4): DIDs with shared social attestations, mutual endorsements, or attestations from the same issuer linking to the same external identity.
- **Governance records**: DIDs flagged as Sybil aliases by context governance (e.g., admin-initiated Sybil reports).
- **Behavioral correlation**: DIDs exhibiting correlated activity patterns (same message timing, same relay, same device attestation) that context-level detection flags.

The expansion mechanism is provided by `expand_block_list`, which accepts a block list and a caller-provided identity resolver callback. The sender key layer does not prescribe the linking strategy — it provides the expansion mechanism. Contexts with higher trust requirements (§9.3) will use more aggressive identity resolution; casual contexts may use none.

**Mitigation 3: Group blocking.** When a Sybil cluster is identified, all linked DIDs SHOULD be blocked atomically in a single key rotation (one epoch advance) rather than N separate rotations. This prevents the Sybil attacker from observing individual blocks and rotating identities between rotations.

**Residual risk.** These mitigations raise the cost and complexity of Sybil block bypass but do not eliminate it. A sufficiently motivated attacker who can satisfy context admission requirements with a fresh DID — one with no attestation linkage to the blocked identity — can still obtain sender keys. This is consistent with the protocol's Sybil resistance philosophy (§9.3): make attacks expensive to sustain, not impossible to attempt. The defense layers compose: membership gates make Sybil identities useless without admission, identity-linked expansion blocks known aliases, and context-level thresholds raise the cost of creating useful new identities.

### 9.16.7 SDK-Mandated State Destruction (Layer 2)

When a block event is received and verified (§9.16.3 step 5), the blocked party's SDK MUST destroy all locally cached material from the blocking party:

1. **Cached sender keys.** Delete all sender key epochs from the blocker. The blocked party cannot request new keys (Layer 1) and MUST NOT retain old keys for historical decryption of the blocker's content. This is a protocol requirement, not a recommendation.
2. **Cached plaintext.** Delete all decrypted message content originating from the blocker. Application-layer caches (message databases, search indices) MUST be purged of the blocker's content.
3. **Cached access keys.** If access keys (§9.17) are in use, delete the blocker's access key for the blocked party. This makes stored ciphertext from the blocker undecryptable at the relay level.

**Compliance requirement.** SDK-mandated destruction is a protocol requirement for compliant clients. An SDK that retains cached material from a blocking party after receiving a verified block notification is non-compliant. The protocol cannot prevent a determined adversary from forking the SDK, but the default behavior of all compliant implementations enforces destruction. This is consistent with the protocol's trust model: the blocker trusts the blocked party's SDK to be compliant (same as trusting MLS implementations to delete old epoch keys).

**Timing.** Destruction MUST occur before the SDK processes any subsequent messages. The block notification handler is synchronous with respect to message processing — no messages from the blocker are decrypted between receiving the block notification and completing destruction. In practice, this means the block handler runs in the message processing pipeline, not in a background task.

**Batch processing.** When processing a catch-up queue (multiple messages in a batch), the block notification's sequence number determines the enforcement boundary. Messages from the blocker with sequence numbers LOWER than the block notification were legitimately sent before the block and SHOULD be processed normally. Messages with sequence numbers HIGHER than the block notification MUST be discarded. The SDK MUST drain pre-block messages from the batch before executing destruction.

### 9.16.8 Unblocking (Forward-Only Restoration)

Unblocking reverses the key distribution denial (Layer 1) but does NOT restore historical access:

1. The blocker removes the target DID from their block list (identity private state, §3.7.1).
2. The blocker does NOT rotate their sender key. The current key remains valid.
3. When the previously-blocked party sends a `SenderKeyRequest`, the blocker's SDK checks the updated block list and responds with the current sender key.
4. The previously-blocked party can now decrypt the blocker's future messages (encrypted with the current sender key epoch and all subsequent epochs).

**Historical gap is permanent.** Content encrypted during the block period used sender key epochs that the blocked party never received and cannot retroactively obtain. The blocker's SDK destroyed the blocked party's access keys (Layer 3, §9.17) and the blocked party's SDK destroyed cached material (Layer 2). Neither side retains the material needed to restore historical access. This is by design: the user promise is "if you're blocked, content is gone; if you're unblocked, you can see new content going forward."

**Forward secrecy interaction.** Old sender keys are destroyed on the blocked party's side (Layer 2) and access keys are deleted (Layer 3). Even if the blocked party somehow retained old sender keys (non-compliant SDK), the access key deletion at Layer 3 makes stored ciphertext undecryptable at the relay level. The three layers provide defense-in-depth with distinct coverage:

| Layer | Uniquely handles |
|-------|-----------------|
| 1 (key denial) | Immediate future message protection, O(1) |
| 2 (SDK destruction) | Cached plaintext on target's device |
| 3 (access key) | Retroactive ciphertext revocation at relay |

Layer 2 is a compliance requirement for already-decrypted plaintext, not a cryptographic guarantee — a non-compliant SDK can retain cached plaintext. Layers 1 and 3 provide cryptographic enforcement. All three together make the guarantee robust against distinct failure modes.

**Stacking with governance.** If governance (Tier 3) has also revoked the target's access via `RevokeAccess { access: Read }` or `RevokeAccess { access: Write }`, the identity-level unblock (Tier 1 or 2) does NOT restore access. Both the identity-level block and the governance revocation must be independently reversed. The target's effective access is the intersection (most restrictive) of all active tiers.

## 9.17 Content Access Key Layer

The sender-side key layer (§9.16) provides selective readability through key distribution denial. The content access key layer adds a second cryptographic enforcement mechanism: per-member access keys that wrap content encryption keys (CEKs). Deleting a member's access key makes stored content undecryptable — retroactive revocation that Layer 1 alone cannot achieve.

### 9.17.1 Key Architecture

Each member in a context holds a per-member **access key** — an AES-256 symmetric key generated at join time. Content encryption keys (CEKs) are wrapped (encrypted) with each intended recipient's access key before storage. A member who loses their access key cannot unwrap the CEK, and therefore cannot decrypt the content.

```
Content Encryption:
  plaintext → AES-256-GCM(CEK) → ciphertext
  CEK → AES-256-KW(access_key_alice) → wrapped_cek_alice
  CEK → AES-256-KW(access_key_bob) → wrapped_cek_bob
  ...
  stored: { ciphertext, wrapped_ceks: { alice: wrapped_cek_alice, bob: wrapped_cek_bob, ... } }
```

**Key types:**
- **Content Encryption Key (CEK):** AES-256, generated per message (or per message batch). Encrypts the actual content. Ephemeral — not stored after wrapping.
- **Access Key:** AES-256, per member per context. Generated at join time. Used to wrap/unwrap CEKs. Stored in the member's local key store and distributed via HPKE Base mode (RFC 9180), using the same suite as sender key distribution (§9.16.2): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. The HPKE `info` string for access key distribution MUST use a distinct domain separator: `info = "scp-access-key-v1" || BE32(len(context_id)) || context_id || BE32(len(member_did)) || member_did || epoch_bytes` (vs `"scp-sender-key-v1"` for sender keys). The `aad` is: `aad = BE32(len(context_id)) || context_id || BE32(len(member_did)) || member_did || epoch_bytes`. Where `epoch_bytes` is the 8-byte big-endian encoding of the access key epoch. This prevents cross-protocol key confusion — an HPKE ciphertext produced for sender key distribution cannot be substituted for an access key distribution response (different `info` produces different derived keys).
- **Key Wrapping:** AES-256-KW (RFC 3394). Deterministic, no IV needed. The wrapped CEK is stored alongside the ciphertext.

**AES-256-GCM additional authenticated data (AAD).** Content encryption MUST bind `context_id` as AAD: `AAD = context_id || sender_did || sequence_number`. This prevents ciphertext from being moved between contexts or reordered within a context. The AEAD authentication tag provides integrity verification — no separate content hash is needed.

**Access key request protocol.** `AccessKeyRequest` messages MUST include a signed payload: `{ context_id, requester_did, epoch, timestamp, nonce }` signed with the requester's Active Signing Key or Agent Signing Key (either `#active` or `#agent` is valid — ADR-039). The `nonce` is a 16-byte random value, unique per request. The responder verifies the signature, checks the block list and revocation list, and responds with the HPKE-encrypted access key only if the requester is authorized. **Replay prevention:** The responder validates that the request timestamp is not older than 300 seconds (5 minutes, consistent with the protocol-wide clock skew tolerance §9.14) and not more than 30 seconds in the future (tighter bound — future timestamps indicate clock manipulation rather than legitimate network delay). The responder also verifies that the `nonce` has not been previously seen. The responder maintains a nonce deduplication cache with a 5-minute TTL — nonces are single-use and cached for the duration of the validity window. Requests with expired timestamps or duplicate nonces are rejected.

### 9.17.2 Access Key Lifecycle

1. **Generation.** When a member joins a context, a fresh random 32-byte AES-256 access key is generated by the context creator (or the member who executed the `AddMember` governance action). The access key is distributed to the new member via the same pull-based HPKE Base mode protocol as sender keys (§9.16.2), with the `info` and `aad` parameters specified in §9.17.1.

2. **Normal operation.** Each message sender generates a fresh CEK, encrypts the content, wraps the CEK with each intended recipient's access key, and publishes the wrapped CEKs alongside the ciphertext. In encrypted contexts, this wrapping occurs BEFORE the MLS encryption layer. In broadcast contexts, it occurs before the sender key encryption.

3. **Revocation.** On `RevokeAccess { did, access: Both }` (governance, Tier 3) or on block (Tiers 1-2): the target's access key is deleted from all members who hold it. Without the access key, the target cannot unwrap CEKs for any stored content. This is retroactive — previously decryptable content becomes undecryptable.

4. **Revocation (Write-only).** On `RevokeAccess { did, access: Write }`: the target is excluded from future CEK wrapping (their access key is no longer used for new messages) but existing wrapped CEKs are not deleted. The target can still decrypt historical content with their cached access key.

5. **Restoration.** On `RestoreAccess { did, capabilities }` or unblock: a NEW access key is generated for the target. The new key is used for future CEK wrapping only. Historical wrapped CEKs used the old (deleted) access key — they are permanently inaccessible. This enforces the forward-only restoration guarantee.

6. **Context-wide rotation.** On `RotateContentKeys { reason }`: all access keys are rotated. Every member receives a new access key. Future content uses new CEKs wrapped with new access keys. Historical content remains accessible with old access keys (which members retain locally). This is for periodic hygiene or post-compromise recovery, not for targeted revocation.

### 9.17.3 Wire Format

```rust
pub struct WrappedContent {
    /// AES-256-GCM encrypted content.
    pub ciphertext: Vec<u8>,
    /// AES-256-GCM nonce.
    pub nonce: [u8; 12],
    /// Per-recipient wrapped CEKs. Ordered by member_id for deterministic serialization.
    pub wrapped_ceks: Vec<WrappedCek>,
}

pub struct WrappedCek {
    /// First 8 bytes of SHA-256(member_did) — prevents DID publication.
    pub member_id: [u8; 8],
    /// AES-256-KW wrapped CEK (40 bytes: 32-byte CEK + 8-byte integrity check).
    pub wrapped_key: [u8; 40],
}
```

The `wrapped_ceks` field uses `Vec<WrappedCek>` (not a HashMap) for deterministic serialization and to avoid hash-table overhead in the wire format. Recipients scan linearly for their `member_id` — for typical context sizes (<1000 members), linear scan is faster than hash lookup. Truncated DID hashes (8 bytes) avoid publishing full DIDs in the envelope, primarily beneficial for broadcast contexts where the subscriber list is not universally known; applied uniformly across context types for wire format consistency. Collision probability for 8-byte hashes is negligible for context sizes up to millions of members. Integrity verification uses AES-256-GCM's authentication tag — no separate content hash is needed.

### 9.17.4 Interaction with MLS and Sender Keys

**Encrypted contexts (MLS).** The content access key layer sits INNERMOST (closest to plaintext). Content encryption + CEK wrapping is a single logical operation: generate a CEK, encrypt plaintext with the CEK, wrap the CEK for each recipient. The result is then passed through the sender key and MLS layers:

```
Encryption: plaintext → AES-GCM(CEK) → {ciphertext, wrapped_ceks} → sender_key_encrypt → MLS_encrypt → relay
Decryption: relay → MLS_decrypt → sender_key_decrypt → unwrap_cek → AES-GCM_decrypt(CEK) → plaintext
```

The access key provides per-member selectivity (Tier 3 governance). The sender key provides per-sender selectivity (Tiers 1-2 blocking). MLS provides group confidentiality against outsiders. All three layers are independent — revoking any single layer's key is sufficient to deny access.

**Broadcast contexts.** The content access key layer is innermost, with the broadcast key as the outer layer:

```
Encryption: plaintext → AES-GCM(CEK) → {ciphertext, wrapped_ceks} → broadcast_key_encrypt → relay
Decryption: relay → broadcast_key_decrypt → unwrap_cek → AES-GCM_decrypt(CEK) → plaintext
```

Because `WrappedContent` (including the `wrapped_ceks` entries) is inside the broadcast key encryption boundary, the relay and non-subscribers cannot observe the wrapped CEK entries. This prevents the `wrapped_ceks` from serving as a membership enumeration oracle.

### 9.17.5 Revocation Mechanics

**Both-scope revocation (retroactive):**

1. The revoker publishes an `AccessKeyRevoked { did, scope: Both, revocation_id, timestamp, signature }` event as an MLS application message. The `revocation_id` is a unique identifier (`SHA-256(context_id || target_did || "access-key-revoke" || timestamp)`). The signature covers `context_id || target_did || scope || revocation_id || timestamp` using the revoker's signing key.
2. Each member's SDK, upon receiving and verifying the `AccessKeyRevoked` event:
   a. Deletes the target's access key from the local key store.
   b. Adds the target's DID to the local access key revocation list.
   c. Records a `AccessKeyDeletionAck { revocation_id, member_did, timestamp, signature }` in the context event log. The acknowledgment is signed by the member's signing key.
3. The relay retains the ciphertext and wrapped CEKs, but the target's wrapped CEK is now useless — the target's access key (needed to unwrap it) no longer exists on any compliant client.
4. The target cannot request the access key via the pull-based protocol — the key holder checks the revocation list and denies the request (same pattern as sender key block list check).

**Coordinated deletion protocol:**

Coordinated key deletion across a distributed system is fundamentally best-effort — the revoker cannot force deletion on a non-compliant client. The protocol provides the strongest coordination guarantees achievable:

- **Offline members:** Members offline at revocation time receive the `AccessKeyRevoked` event upon reconnecting (MLS guarantees ordered delivery within the group). The SDK processes the deletion immediately on receipt. There is no separate "catch-up" protocol — MLS epoch synchronization (§9.7.2) handles delivery.
- **Deletion verification:** The revoker MAY track `AccessKeyDeletionAck` events in the context log to determine which members have confirmed deletion. If a member has not acknowledged within 24 hours of coming online (observable via presence signals or message activity), the revoker MAY escalate to governance (e.g., request removal of the non-acknowledging member).
- **Non-compliant clients:** A malicious or modified client can retain the key despite the deletion instruction. This is an inherent limitation of distributed key management — the protocol cannot enforce key destruction on adversarial hardware. The mitigation is defense in depth: (a) future messages do not include wrapped CEKs for the revoked target, (b) the revocation is recorded in the event log for auditability, (c) governance can remove persistently non-compliant members from the MLS group entirely.
- **Confirmation timeout:** SDKs MUST publish `AccessKeyDeletionAck` within 30 seconds of processing an `AccessKeyRevoked` event. Failure to publish an ack is not a protocol violation (the member may be offline), but persistently active members who do not acknowledge are flagged for governance review.

**FutureOnly revocation:**

1. The target's DID is added to the exclusion list for future CEK wrapping.
2. New messages do not include a wrapped CEK for the target.
3. The target retains their existing access key and can still unwrap CEKs for historical messages.
4. Effectively a "soft block" — the target can read the past but not the future.

### 9.17.6 Forward Secrecy Interaction

The content access key layer interacts with forward secrecy as follows:

- **CEKs are ephemeral.** Each message gets a fresh CEK. Compromise of one CEK reveals one message, not the entire conversation.
- **Access keys are long-lived within an epoch.** An access key persists from join to revocation (or context-wide rotation). This is necessary for the retroactive revocation property — if access keys rotated frequently, retroactive revocation would only cover the current epoch.
- **Old access keys are retained by legitimate members.** Members keep their access keys for historical message decryption. This is consistent with §9.16.5 — sender keys are also retained for historical access. The boundary is block/revocation events, not time.
- **On revocation, access keys are destroyed.** The target's access key is deleted from all compliant clients (Layer 3). The key is not archived or escrowed. This is permanent — there is no mechanism to restore historical access after a Full revocation.

### 9.17.7 Performance Characteristics

| Operation | Cost | Notes |
|-----------|------|-------|
| CEK generation | 32 bytes random | Per message or per batch |
| CEK wrapping | AES-256-KW per recipient | O(N) where N = recipients. ~0.1μs per wrap |
| CEK unwrapping | Single AES-256-KW | O(1) for the recipient |
| Access key distribution | HPKE per new member | Same as sender key distribution |
| Full revocation | Delete from local stores | O(M) where M = members holding the key |
| Storage overhead | 40 bytes per recipient per message | Wrapped CEK = 32-byte CEK + 8-byte KW check value |

For a context with 100 members, each message adds ~4KB of wrapped CEKs (100 × 40 bytes). For broadcast contexts with thousands of subscribers, the wrapped CEK map scales linearly but remains small relative to content size. Contexts with >10,000 members SHOULD use batched CEK wrapping (wrap once per batch of messages, not per message) to amortize the per-recipient cost.

## 9.18 Protocol Constants Registry

This section consolidates protocol-level constants organized into three tiers per ADR-043:

- **§9.18.A — Protocol Invariants.** Fixed values that all implementations MUST agree on. Using different values causes interoperability failures.
- **§9.18.B — Configurable Parameters.** The protocol defines the mechanism and acceptable range. Deployers, relay operators, or context creators set the actual value. Defaults are provided.
- **§9.18.C — Implementation Recommendations.** Suggested values for SDK authors. Not normative — implementations MAY use different values without breaking interoperability.

Constants within each tier are grouped by subsystem with source references for traceability.

### 9.18.A Protocol Invariants

The following constants are protocol invariants. All implementations MUST use these exact values. Deviations cause interoperability failures.

#### 9.18.1 Cryptographic Primitives

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Signature algorithm | Ed25519 (RFC 8032) | All DID keys, envelope signatures, UCAN, MLS leaf credentials | §9.5 |
| MLS ciphersuite | MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 | RFC 9420 §17.1 | §9.5 |
| HPKE suite (DID-to-DID) | DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM | RFC 9180 Base mode | §9.5 |
| Key distribution HPKE | DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM | Same suite for sender key, access key, broadcast key | §9.5 |
| Merkle tree hash | SHA-256 | RFC 6962 §2 construction | §9.5 |
| Merkle leaf prefix | `0x00` | `SHA-256(0x00 \|\| event_data)` | §9.5 |
| Merkle interior prefix | `0x01` | `SHA-256(0x01 \|\| left \|\| right)` | §9.5 |
| Empty tree root | `SHA-256("")` = `e3b0c442...7852b855` | Hash of empty string | §9.5 |
| CEK size | 32 bytes | AES-256 key for content encryption | §9.17 |
| CEK wrapped overhead | 8 bytes | AES-256-KW check value | §9.17.7 |
| HPKE nonce size | 12 bytes | Managed internally by RFC 9180 | §9.5 |
| Ed25519 signature size | 64 bytes | Fixed | §9.5 |
| Ed25519 public key size | 32 bytes | Fixed | §9.5 |
| X25519 public key size | 32 bytes | Fixed | §9.5 |

#### 9.18.2 Domain Separators

All domain separators are UTF-8 strings used as prefixes in canonical hash constructions (§9.5.1). Each separator identifies the struct type being hashed to prevent cross-protocol hash confusion.

| Domain Separator | Used For | Spec Reference |
|------------------|----------|----------------|
| `"SCP-INNER-ENVELOPE-V1:"` | InnerEnvelope signing | §9.5.2 |
| `"SCP-BROADCAST-ENVELOPE-V1:"` | BroadcastEnvelope signing | §9.5.2 |
| `"SCP-EPOCH-ADVANCE-V1:"` | SenderKeyEpochAdvance signing | §9.5.2 |
| `"SCP-KEY-REQUEST-V1:"` | SenderKeyRequest signing | §9.5.2 |
| `"SCP-ATTESTATION-V1:"` | Attestation signing | §9.5.2 |
| `"SCP-PARTICIPATION-V1:"` | ParticipationProfile signing | §9.5.2 |
| `"SCP-PARTICIPATION-PROFILE-V1:"` | ParticipationProfile canonical hash | §9.5.2 |
| `"SCP-BLOCK-NOTIFICATION-V1:"` | BlockNotification signing | §9.5.2 |
| `"SCP-ACCESS-KEY-REQUEST-V1:"` | AccessKeyRequest signing | §9.5.2 |
| `"SCP-VOTE-V1:"` | Governance vote signing | §9.5.2 |
| `"SCP-PROPOSAL-V1:"` | Governance proposal ID computation | §9.5.2 |
| `"SCP-MIGRATION-V1:"` | DID migration proof | §9.12 |
| `"SCP-RESET-REQUEST-V1:"` | Sync reset request signing | §23.5.2 |
| `"SCP-KEY-CONTINUITY-V1:"` | Key continuity fingerprint hash | §9.11 |
| `"SCP-ABSENT-AGENT-KEY"` | Sentinel for absent `#agent` key in continuity fingerprint — `SHA-256("SCP-ABSENT-AGENT-KEY")` | §9.11 |
| `"SCP-CHECKPOINT-V1:"` | Event log checkpoint hash | §11 |
| `"SCP-EVENT-V1:"` | Event log entry hash | §11 |
| `"SCP-EXPORT-ENTRY:"` | Context export chain hash | §5.13 |
| `"SCP-TOOL-REGISTRATION-V1:"` | Tool registration integrity hash | §6.2 |
| `"SCP-KEY-DESTRUCTION-V1:"` | Key destruction proof | §9.15 |
| `"SCP-CLAIM-V1:"` | Shadow identity claim validation | §12.3 |
| `"SCP-RECEIPT-V1:"` | Payment receipt signing | §19.15.5 |
| `"SCP-HANDLE-TOOL-V1:"` | Handle and scope tool request signing | §22.3.1, §22.3.5 |
| `"SCP-CHALLENGE-REQ-V1:"` | Trust challenge request signing | §7.4 |
| `"SCP-CHALLENGE-RESP-V1:"` | Trust challenge response signing | §7.4 |
| `"SCP-CHALLENGE-VERIFY-V1:"` | Trust challenge verification signing | §7.4 |
| `"SCP-BRIDGE-REGISTER-V1:"` | Bridge relay registration signing | §12 |
| `"SCP-PRIVATE-LOG-V1:"` | Private state event hash chain | §3.7 |
| `"SCP-PUSH-REGISTER-V1:"` | Push notification registration signing | §22.11.4 |
| `"SCP-PUSH-DEREGISTER-V1:"` | Push notification deregistration signing | §22.11.4 |
| `"SCP-CHUNK-MSG-ID-V1:"` | Chunked message ID derivation | §9.10.3 |
| `"SCP-COMMIT-RANGE-REQ-V1:"` | Commit range request signing | §23.16.2 |
| `"SCP-COMMIT-RANGE-RESP-V1:"` | Commit range response signing | §23.16.3 |
| `"SCP-CONTEXT-SNAPSHOT-V1:"` | Context snapshot signing | §23.16.4 |

#### 9.18.3 Key Derivation and HPKE Labels

This section consolidates all HKDF labels, HPKE info prefixes, HMAC domain strings, and MLS exporter labels. Each label provides domain separation for a specific key derivation or encapsulation protocol.

**HPKE info prefixes** — used in `info` parameter of RFC 9180 HPKE encapsulation:

| Info Prefix | Used For | Full Format | Spec Reference |
|-------------|----------|-------------|----------------|
| `"scp-sender-key-v1"` | Sender key HPKE encapsulation | `"scp-sender-key-v1" \|\| BE32(len(context_id)) \|\| context_id \|\| BE32(len(sender_did)) \|\| sender_did \|\| epoch_BE` | §9.16.2 |
| `"scp-access-key-v1"` | Access key HPKE encapsulation | `"scp-access-key-v1" \|\| BE32(len(context_id)) \|\| context_id \|\| BE32(len(member_did)) \|\| member_did \|\| epoch_bytes` | §9.17.1 |

**HKDF labels** — used in HKDF-SHA-256 `salt` or `info` parameters:

| Label | Type | Used For | Spec Reference |
|-------|------|----------|----------------|
| `"scp-private-state-salt-v1"` | HKDF salt domain | Private state routing ID derivation — actual salt is `SHA-256("scp-private-state-salt-v1")` | §3.7 |
| `"scp-private-state-v1"` | HKDF info prefix | Private state routing ID derivation — full info is `"scp-private-state-v1" \|\| did_string` | §3.7 |
| `"scp-bridge-credential-v1"` | HKDF info | Bridge credential encryption key derivation | §12 |
| `"scp-participation-statement-v1"` | HKDF info | Context-specific participation signing key derivation | §7.3 |

**HMAC domain separators** — used in HMAC-SHA-256 for pseudonym key derivation:

| Label | Used For | Construction | Spec Reference |
|-------|----------|--------------|----------------|
| `"scp-pseudonym"` | Pseudonym v1 (non-rotatable, epoch 0) | `HMAC-SHA-256(identity_key_material, context_id \|\| "scp-pseudonym")` | §9.2 |
| `"scp-pseudonym-v2"` | Pseudonym v2 (rotatable, epoch > 0) | `HMAC-SHA-256(identity_key_material, context_id \|\| epoch_BE \|\| "scp-pseudonym-v2")` | §9.2 |

**MLS exporter labels** — used in RFC 9420 `MLS-Exporter` for key export:

| Label | Used For | Spec Reference |
|-------|----------|----------------|
| `"scp-media-key-v1"` | DTLS-SRTP media key derivation from MLS group state | §10.9.1 |

#### 9.18.4 Key and Nonce Sizes

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Access key nonce size | 16 bytes | CSPRNG, prevents replay in access key requests | §9.17 |
| Sender key request nonce size | 16 bytes | CSPRNG, prevents replay in key requests | §9.16.2 |
| Member ID size | 8 bytes | Truncated SHA-256 of member DID | §9.17 |
| AES-GCM nonce size | 12 bytes | For sender key and access key AEAD | §9.16, §9.17 |
| Sender key size | 32 bytes | AES-256-GCM key | §9.16 |
| Access key size | 32 bytes | AES-256 wrapping key | §9.17 |
| AES-KW IV | `[0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]` | RFC 3394 Initial Value for AES Key Wrap | §9.17 |
| AES-KW semiblocks | 4 | Number of 64-bit semiblocks in 256-bit key | §9.17 |

#### 9.18.5 Envelope and Padding

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Padding bucket sizes | `[256, 1024, 4096, 16384, 65536, 262144]` | Payloads padded to next bucket boundary | §9.10 |
| Max chunk payload size | 262140 bytes | Largest bucket (262144) minus 4-byte length suffix | §9.10 |
| Length suffix size | 4 bytes | BE u32, appended before padding | §9.10 |
| Max total chunks | 262,144 | Maximum chunks per chunked message (~64 GB theoretical max) | §9.10 |
| Max bounded binary field | 524,288 bytes (512 KiB) | OOM-prevention limit for binary fields on deserialization | §9.5 |
| Max outer envelope wire size | 589,824 bytes (576 KiB) | `MAX_BOUNDED_BINARY + 65,536` — checked before deserialization | §9.5 |
| Max bounded string field | 1,024 bytes | OOM-prevention limit for string identifier fields | §9.5 |

#### 9.18.6 Context and Governance (Invariants)

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Max tool interfaces per context | 256 | Hard cap on registered tool interfaces | §6.2 |
| Ceiling change notification period | 259,200s (72h) | Members notified before ceiling change takes effect | §5.3.2 |
| Freeze timeout | 172,800s (48h) | Frozen context auto-unfreezes after this period | §5.6 |
| Default context verification window | 300s (5 min) | Grace period for context close verification | §5.6 |
| Tool lifecycle default timeout | 30,000ms (30s) | Default tool invocation timeout | §6.2 |
| Tool lifecycle max timeout | 300,000ms (5 min) | Hard protocol maximum for tool invocation timeout | §6.2 |
| Min active voters for fallback | 2 | Minimum voters for governance timeout fallback | §6.4 |
| Max threshold signers | 64 | Maximum co-signers for multi-sig governance actions | §5.6 |
| Max role name length | 64 bytes | Maximum length of custom role names | §5.6 |

#### 9.18.7 MLS and UCAN

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Max grace epochs | 100 | Maximum MLS epochs retained for grace-period decryption | §9.7 |
| Grace window duration | 30s | Time window for accepting messages from prior epochs | §9.7 |
| UCAN max expiry | 86,400s (24h) | Maximum UCAN token lifetime; matches nonce dedup cache | §9.8.2 |
| UCAN nonce freshness tolerance | 300,000ms (5 min) | Clock skew tolerance for UCAN nonce timestamps | §9.8.2 |
| UCAN nonce prune expiry grace | 300s (5 min) | Grace period before expired nonces are garbage collected | §9.8.2 |
| Default UCAN revocation TTL | 30s | Default TTL for revocation propagation confirmation | §9.8.2 |
| CID version | CIDv1 (prefix `0x01`) | For UCAN token identification | §9.5 |
| CID hash algorithm | SHA-256 (multihash `0x12`) | 32-byte digest | §9.5 |
| CID content codec | DAG-CBOR (`0x71`) | Canonical CBOR encoding | §9.5 |
| CID multibase encoding | base32lower (prefix `b`) | For display; raw bytes on wire | §9.5 |
| MLS extension type: `scp_wrapping_key` | `0xFF01` | RFC 9420 §17.3 private-use range; carries X25519 sender key wrapping public key | §9.16 |
| UCAN max delegation chain depth | 32 | Maximum depth of UCAN delegation chains | §9.8.2 |
| UCAN nonce cache max capacity | 100,000 | Maximum nonces tracked for deduplication | §9.8.2 |
| UCAN nonce min retention | 86,400s (24h) | Minimum time nonces are retained before garbage collection | §9.8.2 |

#### 9.18.8 Sender Key Protocol

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Sender key grace period | 30s | Window for accepting messages with pre-rotation keys. Protocol invariant per ADR-001 criterion 6 — bounds the forward secrecy window. Not configurable. | §9.16 |
| Sender key nonce expiry | 300s (5 min) | Validity window for sender key request nonces | §9.16.2 |
| Sender key request freshness | 300s (5 min) | Request freshness window (synchronized with nonce expiry) | §9.16.2 |
| Block notification freshness | 30,000ms (30s) | Maximum age for block notification messages | §9.16.4 |
| Sender key nonce dedup capacity | 10,000 | Maximum nonces tracked for sender key replay prevention | §9.16.2 |
| Access key request max age | 300s (5 min) | Maximum age for access key request messages (past window). Aligned with protocol-wide clock skew tolerance (§9.14). | §9.17.1 |
| Access key request max future | 30s | Maximum future tolerance for access key request timestamps. Tighter than past window — future timestamps indicate clock manipulation, not network delay. | §9.17.1 |
| Sender key header size | 16 bytes | `epoch (8B BE) \|\| sequence (8B BE)` prepended to sender-key ciphertext inside MLS plaintext | §9.16.1 |
| SCPM management magic | `[0x53, 0x43, 0x50, 0x4D]` | 4-byte ASCII prefix distinguishing management from application messages in MLS plaintext | §9.16.1 |
| Management payload max size | 65,536 bytes (64 KiB) | Maximum management message payload after SCPM prefix | §9.16.1 |
| Epoch poisoning max advance | 1,000 | Maximum allowed epoch jump in a single sender key distribution | §9.16.1 |
| Buffer event max age | 3,600s (1h) | Maximum estimated age for buffer events in consequence evaluation | §7.3.7 |
| Buffer event future tolerance | 5s | Maximum future tolerance for buffer event timestamps | §7.3.7 |
| Broadcast replay max authors | 10,000 | Maximum unique senders tracked in broadcast replay detector | §9.16.5 |

#### 9.18.9 Sync and Offline Recovery (Invariants)

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Tier 1 threshold (minutes offline) | 14,400s (4h) | Below: sequential commit replay | §23 |
| Tier 2 threshold (days offline) | 604,800s (7d) | Below: snapshot + delta; above: full reset | §23 |
| Commit process timeout | 5s | Timeout for individual commit processing | §23 |
| Gap timeout | 30s | Timeout waiting for missing epochs before escalating | §23 |
| Default snapshot interval | 14,400s (4h) | How often Tier 2 snapshots are generated | §23 |
| Reset welcome timeout | 60s | Timeout for receiving MLS Welcome after reset request | §23.5 |
| Max epoch drift (Tier 3) | 1,000 epochs | Maximum epoch gap before requiring full reset | §23.5 |
| Reset request nonce cache | 10,000 entries | Anti-replay cache for reset request nonces | §23.5 |
| Max inflight reset queue | 500 | Maximum concurrent pending reset requests | §23.5 |
| Reorder buffer capacity | 100 | Capacity of message reorder buffer for out-of-order delivery | §23 |
| Reset request freshness | 30s | Freshness window for Tier 3 reset request signatures | §23.5 |
| Reset request nonce TTL | 60s | TTL for Tier 3 reset request nonces in anti-replay cache | §23.5 |

#### 9.18.10 Event Log

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Checkpoint event interval | 50 events | Events between automatic checkpoints | §11 |
| Checkpoint time interval | 600s (10 min) | Time between automatic checkpoints | §11 |
| Hot tier age threshold | 604,800s (7d) | Events older than this move to cold tier | §11 |
| Max hot events | 10,000 | Maximum events retained in hot tier | §11 |
| Max hot bytes | 52,428,800 (50 MiB) | Maximum bytes retained in hot tier | §11 |
| Min retention (prune) | 2,592,000s (30d) | Minimum event retention before pruning is allowed | §11 |

#### 9.18.11 Transport and Relay

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Default blob TTL | 3,600s (1h) | Default time-to-live for stored blobs | §10.5 |
| Min blob TTL | 1s | Minimum allowable blob TTL | §10.5 |
| Max blob TTL | 604,800s (7d) | Maximum allowable blob TTL | §10.5 |
| Max ref ID length | 64 bytes | Maximum length of message reference IDs | §10.5 |
| Default query limit | 100 messages | Default message batch size for queries | §10.5 |
| Max query limit | 1,000 messages | Maximum message batch size for queries | §10.5 |
| Ping interval | 30s | Client-to-relay keepalive interval | §10.5 |
| Max reconnect attempts | 6 | Maximum consecutive reconnection attempts | §10.5 |
| Reconnect overlap | 5s | Overlap window during relay reconnection for gap-filling | §10.5 |
| Relay timestamp deviation threshold | 60s | Maximum acceptable clock skew between client and relay | §10.5 |
| Max blob size | 262,144 bytes (256 KiB) | Maximum blob payload size on relay (matches largest padding bucket) | §10.5 |

#### 9.18.12 Bridge

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Max shadows per bridge | 10,000 | Maximum shadow identities per bridge connector | §12.3 |

#### 9.18.13 Discovery and Addressing

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Handle max length | 64 characters | Maximum `local-part` length for handles | §22.2 |
| Handle charset | `[a-z0-9._-]` | Allowed characters in handle local-part | §22.2 |
| Domain handle cache TTL | 3,600s (1h) | Resolution cache lifetime for domain handles | §22.8.4 |
| Discovery handle cache TTL | 900s (15 min) | Resolution cache lifetime for context handles | §22.8.4 |
| Petname cache TTL | 31,536,000s (1 year) | Resolution cache lifetime for petnames | §22.8.4 |
| Attestation handle cache TTL | 86,400s (24h) | Resolution cache lifetime for attestation handles | §22.8.4 |
| Discovery cache default capacity | 10,000 entries | Default capacity for the resolution cache | §22.8.4 |
| Max context writers | 500 | Maximum writer members in a context with discovery tools | §22.3 |
| Push platform tag: APNS | `0x01` | Platform tag byte for Apple Push Notification Service | §10.7.1 |
| Push platform tag: FCM | `0x02` | Platform tag byte for Firebase Cloud Messaging | §10.7.1 |
| Push platform tag: WebPush | `0x03` | Platform tag byte for Web Push API | §10.7.1 |

#### 9.18.14 Version Constants

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| SCP protocol version | `0x0100` (u16) | SCP/1.0, encoded as `(major << 8) \| minor`; first field in all envelope types | §9.5 |
| Inner envelope version | `1` (u8) | Inner envelope format version | §9.5 |

#### 9.18.15 Timestamp and Message Validation

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Default clock skew tolerance | 300,000ms (5 min) | Maximum acceptable clock skew for envelope timestamp validation | §9.5 |
| Default max message age | 604,800,000ms (7d) | Messages older than this are rejected regardless of clock skew | §9.5 |

#### 9.18.16 Membership and Buffers

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| Default receive buffer capacity | 1,000 events | Default in-memory event receive buffer per membership | §5.6 |
| Min receive buffer capacity | 100 events | Minimum configurable buffer capacity | §5.6 |
| Max receive buffer capacity | 10,000 events | Maximum configurable buffer capacity | §5.6 |
| Default key package min buffer | 10 | Minimum MLS key packages to keep available | §9.7 |
| Key package replenish threshold | 5 | Trigger replenishment when buffer drops below this | §9.7 |

#### 9.18.17 External Constraints

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| DHT republish interval | 7200s (2h) | External constraint (BEP44 expiry). Not configurable — the DHT requires periodic republishing within its expiry window. | §3.3 |

### 9.18.B Configurable Parameters

The following constants have protocol-defined mechanisms and acceptable ranges, but the actual value is set by the context creator, relay operator, or deployer. Defaults are provided for when no explicit value is configured. Per ADR-043.

| Parameter | Default | Range | Mechanism | Spec Reference |
|-----------|---------|-------|-----------|----------------|
| Nesting depth | Unbounded (no protocol ceiling) | [1, u32 max] | `ContextParams::max_nesting_depth`. `None` = unbounded; contexts MAY set a limit. | §5.13.8 |
| Chain depth | 8 hops | [1, 255] (u8) | `ContextParams::max_chain_depth`. `None` = use default. No protocol hard max. | §24.4 |
| Session cap per caller | 1000 | [1, u32 max] | `ContextParams::session_cap`. `None` = use default. | §6.2.1 |
| Relay blob TTL | 604,800s (7d) | [1, infinity] | Relay operator configuration. | §10.5 |
| Relay republish interval | Derived: `max(ttl - 86400, ttl / 2, 60)` | Derived from TTL | Computed from relay blob TTL. Floor of 60s prevents spin loop at very small TTLs. | §10.5 |

### 9.18.C Implementation Recommendations

The following values are RECOMMENDED defaults for SDK implementations. They are not normative — implementations MAY use different values without breaking protocol interoperability. Per ADR-043.

| Parameter | Recommended Value | Notes | Spec Reference |
|-----------|-------------------|-------|----------------|
| Max sequential commits (catch-up) | 100 epochs | Hardware-dependent. Already configurable via `SyncPolicy`. | §23 |
| Sender key timeout | 60s | SDK decides retry strategy. Already configurable via `SyncPolicy`. | §9.16.2 |
| Reconnection timeout | 120s | Overall reconnection timeout. SDK decides retry strategy. | §23 |
| Reconnection dedup window | 30s | Multi-device reconnection deduplication. Already configurable via `SyncPolicy`. | §23 |
