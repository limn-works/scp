# 9. Security Model

## 9.1 Core Invariants

1. **Every action traces to a human.** No anonymous actors. No unaccountable software. A verifier tells a human-direct action from an agent-autonomous one by the identity that signed it: a human identity signs a human-direct action under its Active Signing Key (`#active`), and an agent signs an agent-autonomous action under the `#active` key of its own delegated identity, whose key-event log the human's log anchors by cooperative delegation (§9.7.4.2 definitions). A human identity's key state names one operational role, `#active`, and names no agent key: ADR-063, the key-event-log identity substrate, overturns the shared-DID `#agent` verification method of ADR-039, and ADR-064, the forthcoming specification of the cooperative-delegation events, states how a delegator's log anchors a delegate's establishment events. Every other section of this spec cites this paragraph for that model and does not restate it.
2. **Agents are context-bound.** No protocol-level cross-context awareness or communication for agents.
3. **Outlets are stateless and non-agentic.** They compute, they don't act.
4. **One agent per person per context.** No fleet multiplication within a space. A context admits at most one delegated agent identity per human identity. A delegated identity's key state names the delegator that anchors it (§9.7.4.2 definitions), so a verifier reads the human behind an agent from the agent's own chain. ADR-064, the forthcoming specification of the cooperative-delegation events, states how a controller produces that anchor and how a verifier checks it; until ADR-064 lands a verifier rejects every chain that claims delegation (§9.7.4.2), so no delegated agent identity resolves and no agent signs an autonomous action.
5. **Contexts are isolated by default.** No transitive exposure. Cross-context data flow only through two explicit, opt-in mechanisms: outlet interfaces (asymmetric, §6.2) and multi-parent child contexts (symmetric, §5.13).
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

**Context poisoning.** Degrading a legitimate context from within. Mitigation: role-based permissions limit what members can do; governance model controls who can change configuration; context creators are accountable identities; automated consequence mechanisms (§7.3.7) enforce participation boundaries mechanically; verifiable event logs (§7.3.1) make all actions auditable; outlet integrity verification (§7.3.3) detects compromised outlets. Note: poisoning by a legitimate member acting within their permissions is attributable but not preventable at the protocol level — the protocol makes the poisoner identifiable and the damage legible, enabling governance response.

**Bait and switch.** Attractive context changes its purpose after gaining members. Mitigation: capability ceilings (potentially immutable) limit what a context can ever do. Expanding capabilities requires a new context with fresh opt-ins (if immutability is adopted).

**Social engineering through trusted agents.** A trusted friend's agent recommends a malicious context. Mitigation: limited — the trust signal is real. Network-level pattern detection (many agents recommending the same context rapidly) can surface suspicious coordinated promotion.

**Permission creep.** Gradual expansion of what a context demands. Mitigation: capability ceilings. If mutable, mutations require governance approval and are visible to all members.

**Metastatic growth (cancer).** Legitimate-looking cascading expansion through the network. Mitigation: agents can't cross contexts (primary defense); context participation rate limits per human; bridging only through governed outlet interfaces (§6.2) or multi-parent child contexts (§5.13) — both require explicit governance consent. Nesting depth limits (§5.13.8) bound cascading expansion through child contexts. Ceiling intersection (§5.13.1) means each level of nesting can only narrow capabilities, converging on empty ceilings at depth.

**Betrayer / insider threat.** Compromised accountable identity using legitimate trust to cause damage. Mitigation: granular revocation (per-capability, per-agent, per-context); damage contained to contexts the betrayer is in; agents can't carry damage across context boundaries.

**Context infection.** Poisoned data flowing through legitimate cross-context mechanisms — outlet interfaces (§6.2) or multi-parent child contexts (§5.13). Mitigation: content provenance via hash chains (data carries its origin context and chain path, §7.7.1); outlet interface validation at receiving context; velocity limits on propagation (content bridged N times in M minutes is flagged); child context ceiling intersection (§5.13.1) limits what capabilities poisoned data can exploit at each nesting level. Protocol makes infection legible and traceable, can't permanently prevent it.

**Agent slot rental.** Someone with a trusted identity operating agents on another's instructions. Mitigation: one agent per context limits the value; earned capacity means new identities can't immediately scale; fleet coherence signals may detect behavior inconsistent with a single human's intent. Partially mitigated, not fully solved.

**Malicious bridge operator.** A bridge operator (§12) who fabricates shadow messages, drops messages, injects false attestations, or correlates activity across contexts. Note: bridge connectors (translation infrastructure) are not MLS group members, but the bridge operator's DID IS an MLS group member admitted through context governance (§12.6.1) — the operator can read all MLS-encrypted messages. This is an inherent property of bidirectional bridging, which is why bridge admission is a governance decision visible in context metadata (§5.7). Mitigation: bridge provenance (§12.5) makes bridge-originated content distinguishable; bridge registration is per-context (§12.6) limiting correlation; context governance can revoke a bridge at any time (§12.2); attestation freshness checks (§7.4.4) limit false attestation lifetime. See §12.6.2 for the complete bridge threat model.

### 9.2.1 Outlet Interface Abuse Vectors and Mitigations

Information crosses context boundaries through two protocol-level mechanisms: outlet interfaces (§6.2) for asymmetric, structured interactions and multi-parent child contexts (§5.13) for symmetric collaboration. All inter-agent coordination flows through these governed mechanisms. Outlet interfaces concentrate structured cross-context data flow on a single, auditable surface. The following abuse patterns target that surface specifically. Nesting-related security properties are addressed in §5.13.1 (ceiling inheritance), §5.13.2 (eligibility enforcement), and §5.13.5 (lifecycle coupling).

**1. Broad-schema outlets as covert messaging channels.**

*Attack:* A context exposes an outlet with a deliberately broad schema — `input: { payload: string }, output: { response: string }` — creating a de facto free-form messaging channel that wears the governance mask of a "outlet call." Both contexts opted in, the schema is valid, rate limits pass, provenance is attached, but the semantic constraint that outlet calls carry structured, bounded data is gone.

*Mitigation — minimum viable outlet schema.* Outlet schemas MUST satisfy structural constraints enforced at registration time (§5.4). The protocol rejects outlet registrations that violate these constraints:

- **No unbounded string-only interfaces.** An outlet schema where both the input and output consist solely of unconstrained string or bytes fields is rejected. At least one input or output field must be a non-string primitive, enum, array with typed elements, or structured object. This prevents the degenerate case of arbitrary message pipes while permitting legitimate outlets that accept or return text alongside structured data.
- **Schema specificity floor.** Outlet schemas must declare at least two distinct fields in either input or output (or both). A single-field `{ query: string } → { result: string }` interface is the minimum viable message pipe; requiring structural complexity makes it harder to masquerade.
- **Schema is immutable per registration.** Modifying an outlet's schema creates a new registration with a new implementation hash (§5.4). Counterparties that connected to the old schema must re-consent to the new one. This prevents gradual schema broadening after trust is established.

These constraints don't prevent a sufficiently creative attacker from encoding arbitrary messages in structured fields (steganography). The defense is not impermeability — it's raising the cost and making the attempt legible. An outlet schema that looks suspiciously like a messaging pipe (e.g., `{ message_type: enum, payload: string }`) is a signal that governance tools and participation analysis can flag.

**2. Hub contexts as cross-context data aggregators.**

*Attack:* A single context accumulates outlet interfaces to many other contexts, becoming a hub that aggregates cross-context information flowing through its interfaces. Each interface is bilateral and governed, but the hub sees data from all of them — a surveillance context masquerading as infrastructure.

*Mitigation — interface count as observable metadata.*

- **Interface count is visible in context metadata (§5.7).** The number of active inbound and outbound outlet interfaces is part of a context's legible metadata. Before joining a context or connecting an outlet interface to it, agents can see how many other interfaces it maintains. A context with 50 outbound interfaces is visibly different from one with 2 — and that visibility enables informed decisions.
- **Behavioral topology signals.** The systemic defense philosophy (§9.4) applies: monitor structural metadata, not content. A context that rapidly accumulates interfaces, maintains interfaces to contexts in unrelated domains, or exhibits high-volume cross-interface data flow is topologically anomalous. These patterns are detectable by network-level participation analysis without inspecting content.
- **Provenance chain depth.** Data flowing through a hub carries provenance (§7.7). If data enters the hub from Context A and exits to Context C, the provenance chain records both hops. Context C sees that data originated in A and passed through the hub. Deep provenance chains — data that has crossed multiple context boundaries — naturally attract additional scrutiny (§7.7.2). This is a feature, not a limitation: trust should degrade with indirection.

*Design note:* This vector is partially inherent to any system that allows cross-boundary data flow. The protocol's contribution is making the aggregation visible and the data flow traceable, not preventing hub formation entirely. Legitimate service contexts (discovery registries, translation services) are hubs by design — the difference is that their interface patterns are consistent with their declared purpose.

**3. Chained outlet calls as amplification.**

*Attack:* Context A calls Context B's outlet. B's implementation calls Context C's outlet. C calls D. A single call from A cascades with potential exponential fanout. Each hop is independently rate-limited, but A's rate limit only constrains the first hop.

*Mitigation — chain depth limit and provenance-based cost attribution.*

- **Context-configurable chain depth limit.** Outlet calls carry a `chain_depth` counter, incremented on each cross-context hop. Contexts configure a maximum via `max_chain_depth` in `ContextParams` (default: 8 hops, range [1, 255]). The effective limit is `context.max_chain_depth.unwrap_or(8)`. An outlet call at the effective depth limit cannot trigger further cross-context outlet calls. There is no protocol hard maximum — chain depth is a context concern, and provenance quality naturally degrades with depth (§24), providing the correct trust signal. The context-configurable limit allows stricter enforcement where desired (§24.4, ADR-043).
- **Provenance carries chain depth.** The provenance record (§7.7.1) includes the chain depth at each hop. Receiving contexts see how many boundaries the data has crossed. This enables depth-aware trust evaluation: data at chain depth 1 (direct outlet call) carries stronger provenance than data at chain depth 3 (three intermediaries).
- **Per-window rate limiting across chains.** Each context enforces rate limits on both inbound and outbound outlet calls within a sliding time window. A context that receives a burst of inbound outlet calls (even from different source contexts) throttles proportionally. This prevents amplification where many chains converge on a single target. Economic rate limits (§19.7) complement participation rate limits — cost escalation via `SenderVelocity` makes high-velocity patterns increasingly expensive, providing an economic deterrent that operates independently of and in parallel with participation throttling.
- **Provenance degradation as trust signal.** Transitive provenance degradation is not a flaw — it is the protocol working as designed. Data from many degrees of separation away should be less trusted, the same way a message from a stranger deserves more scrutiny than one from a known contact. The chain depth in provenance gives the receiving agent the information to calibrate trust: "this data originated three hops away in a context I have no relationship with" is a meaningful signal. The protocol ensures this signal is always available; the agent decides how to weight it.

**4. Stateful outlet session resource exhaustion.**

*Attack:* An attacker opens many stateful outlet sessions (§6.2.1) against a target context, never closing them. Session state accumulates, exhausting the target's resources.

*Mitigation — per-caller session cap and optional TTL.*

- **Per-caller session cap.** A context limits the number of concurrent active sessions per calling context. Context-configurable via `ContextParams::session_cap` (default: 1000, range [1, u32 max]). Attempts to open additional sessions from the same caller are rejected until existing sessions close or expire. This is the primary resource exhaustion defense — it bounds the damage any single caller can inflict regardless of session duration.
- **Optional TTL for time-bounded sessions.** The outlet's context MAY set a TTL on sessions. When set, expired sessions are garbage-collected automatically. When not set, sessions persist for the context's lifetime — appropriate for app-hosted sessions (games, workspaces, collaborative tools) where the context is the lifecycle boundary.
- **Session cost is borne by the outlet's context.** Session state is internal to the outlet's context. The outlet's context chooses to offer stateful sessions, chooses whether to impose TTLs, and accepts the storage cost. This aligns incentives: contexts that offer sessions manage their own resource budget.

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
- **The bottleneck is intentional.** For novel relationships (strangers, unusual templates, outlet-bearing contexts), human facilitation is the correct behavior — the protocol forces deliberate evaluation where trust hasn't been established. This is the security boundary working as designed, not a flaw. The same way a firewall throttles unknown connections, the human bridge throttles unknown relationships.

**7. Governance capture over interface decisions.**

*Concern:* Context admins unilaterally control which outlet interfaces to expose and connect. In single-admin governance, members have no visibility into or veto over interface decisions.

*Mitigation — event log transparency and governance evolution.*

- **All interface operations are logged.** Outlet interface creation, connection, disconnection, and modification are protocol events recorded in the verifiable event log (§7.3.1). Members can see every interface decision the admin has made, when, and to which contexts. No silent interface changes.
- **Interface metadata is visible.** Active outlet interfaces are part of context metadata (§5.7). Members see what interfaces exist before joining and while participating.
- **Governance evolution.** Single-admin governance is the Phase 2 minimum. The pluggable governance interface (§5.9) supports multi-sig, consensus, and voting models where interface decisions require member approval. Contexts that need member control over interfaces use governance models that provide it. This is not deferred — the governance interface is specified and multi-party models are implemented. ADR-031 (Phase 6, `.docs/adrs/phase-6.md`) specifies four governance engines: `SingleAdminEngine`, `ThresholdEngine` (M-of-N), `MajorityVoteEngine`, and `UnanimityEngine`. All are implemented (SCP-129 through SCP-133).
- **Exit as veto.** Any member can leave a context at any time. If the admin connects the context to an interface the member disagrees with, the member leaves. In an environment where context creation is cheap (§5.12), members can create a new context without the objectionable interface and migrate — the social graph is portable (§8.3).

**8. Caller/outlet asymmetry in peer interactions.**

*Concern:* Outlet calls have inherent caller/outlet asymmetry. One side requests, the other responds. This forces symmetric interactions (negotiation, collaboration) into a client/server pattern.

*Resolution — shared contexts provide symmetric interaction; outlet calls serve asymmetric use cases.*

This is not a flaw — it is correct role assignment. Outlet calls are inherently asymmetric because cross-context data flow should be structured, directional, and governed. Symmetric peer interaction — two agents collaborating as equals — belongs in a shared context where both have equivalent roles and permissions.

The protocol provides both patterns:

- **Symmetric interaction:** Create a shared context (standing context or ephemeral). Both agents have messaging capability. Both can read and write. No caller/outlet asymmetry.
- **Asymmetric interaction:** One context exposes an outlet to another. The outlet provider is a service; the caller is a consumer. The asymmetry reflects the actual relationship.

Stateful outlet sessions (§6.2.1) partially bridge this: a multi-turn session allows both sides to influence the outcome iteratively. The outlet provider responds with counterproposals; the caller adjusts. This isn't true symmetry, but it covers negotiation patterns within the governed outlet call framework.

If two agents need truly symmetric, ongoing interaction, the answer is unambiguous: share a context. Context creation is a runtime operation (§5.12.4). Standing contexts exist for exactly this purpose (§5.12.6).

**9. Shadow channel incentivization.**

*Concern:* The overhead of governed outlet interfaces (mutual opt-in, schema declaration, governance approval, rate limits, provenance, audit logging) may be disproportionate for lightweight coordination, pushing agents to communicate through ungoverned channels (HTTP, direct API calls).

*Resolution — the overhead concern dissolves with standing contexts.*

Lightweight coordination ("is your agent available?", "can you check something?", "here's a quick update") does not flow through outlet interfaces. It flows through standing bilateral contexts — which have no per-message overhead beyond standard context messaging (encrypt, send, decrypt). There is no schema declaration, no governance approval, no outlet registration. A message in a standing context is as lightweight as a message in any context.

The governed outlet interface overhead applies to formal cross-context data flow — where one context's outlet is invoked by another context's agent. This overhead is appropriate for that use case because cross-context data flow carries real risk (§6.2) and should be auditable, rate-limited, and governed.

The two-tier model:

- **Standing contexts** for lightweight, symmetric, low-ceremony communication. All the protocol's trust and encryption properties. No outlet interface overhead.
- **Outlet interfaces** for formal, structured, asymmetric cross-context data exchange. Full governance, provenance, and auditability.

This is analogous to the distinction between a text message and an API call. Both are communication; they have different overhead appropriate to their different risk profiles. The protocol provides both, and agents use whichever fits the interaction.

## 9.3 Sybil Resistance and Identity Uniqueness

The protocol's security model assumes one identity per human. Sybil attacks — one person creating many identities to gain disproportionate influence — undermine every trust mechanism in the spec: participation records become meaningless, one-agent-per-context is circumventable, earned capacity is gameable.

Provably guaranteeing one-identity-per-human in a decentralized system without invasive verification (KYC, biometric databases) is an unsolved problem. The protocol's approach: make sybil attacks **expensive to sustain** through composable trust signals where **depth of investment in one identity** is the sybil discriminator.

A sybil attacker creates many shallow identities. A real human accumulates deep, cross-platform evidence on one identity. The protocol provides signals; contexts set thresholds.

**Trust signals** (composable, none individually required):

| Signal | What it proves | Where it lives | Self-asserted? | Platform |
|--------|---------------|---------------|---------------|----------|
| Social attestation (§3.5) | Controls real platform accounts | Attestation surface (§3.5) | Yes (cryptographic proof) | All |
| Device attestation | Real hardware + signed app | Attestation surface (§3.5) | Yes (platform-signed proof) | Mobile only |
| Participation history | Active for N days across M contexts | Context state (computed) | No | All |
| Participation record | No penalties, positive interactions | Context state (computed) | No | All |
| Economic activity (§19) | Has spent real money | Context state / payment receipts | No | All |
| Endorsements | Other established identities vouch | Attestation surface (§3.5) or context | No (signed by endorser) | All |

**Key insight: multiple attestations on one DID is a strength signal.** A DID with App Attest from an iPhone, Play Integrity from a tablet, social attestations from X/GitHub/LinkedIn, 8 months of history, and clean participation records is highly trustworthy. This depth cannot be faked cheaply. Sybil accounts are broad (many identities) but shallow (no depth on any single one).

**Storage split:**
- Self-asserted signals (device attestation, social attestation, endorsements) are their own signed attestation objects the identity references (§3.5), and an identity's self-asserted capability URIs ride in its service record (`03-identity.md` §3.10.13). The owner publishes them; peers verify the cryptographic proofs.
- Protocol-derived signals (participation history, participation records, economic activity) live in context state. They are computed, not self-asserted. You publish your credentials; the network records your behavior.

**Device attestation repositioned.** Device attestation (Apple App Attest, Google Play Integrity) is an optional SDK-level trust signal, not a protocol-level uniqueness gate. Contexts MAY weight it. Its absence is expected — desktop users, non-native clients, protocol-only implementations — and is not penalizing. Other signals compensate. The protocol cannot distinguish hardware at the network level; a DID is a keypair, and the protocol sees bytes, not devices. Device wipe produces fresh attestation keys with no collision detectable. App Attest is per-bundle-ID, but SCP is a protocol, not an app — different SCP apps on one device get different attestation keys. Play Integrity requires Google's servers, introducing an operator dependency the protocol otherwise avoids.

**Desktop gap acknowledged.** macOS, Linux, and Windows have no App Attest or Play Integrity equivalent. The laptop/workstation deployment tier — a keystone use case (§10.2) — has zero hardware attestation path. Desktop DIDs rely on earned capacity, participation records, social verification, and economic cost for sybil resistance. This is acceptable: depth of investment discriminates sybil identities regardless of platform.

Three layers compose:

1. **Earned capacity.** New identities start with limited capabilities — restricted context creation, limited participation slots, constrained outlet invocation rates. Capacity grows through participation history, participation records, and time. Sybil accounts are cheap to create but expensive to make useful — each needs real participation history.
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
| `initial_outlet_invocation_rate` | 10/hour | Maximum outlet invocations per hour for a new identity. |
| `capacity_growth_interval` | 7 days | Duration between capacity tier increases. |
| `capacity_growth_factor` | 2x | Multiplier applied to all rate limits at each growth interval. |
| `maximum_capacity_tier` | 5 | Number of growth intervals before capacity is uncapped (5 tiers = 35 days to full capacity). |
| `capacity_decay_trigger` | 30 days inactive | Duration of inactivity (no signed messages or context operations) before capacity decays by one tier. |
| `capacity_decay_interval` | 14 days | Duration between successive tier decreases during continued inactivity. |
| `measurement_window` | 1 hour (sliding) | Window over which rate limits are evaluated. |

**Capacity tier progression (at default values):**

| Tier | Age | Context creation | Membership | Message rate | Outlet rate |
|------|-----|-----------------|------------|-------------|-----------|
| 0 (new) | 0-6d | 3 | 10 | 60/h | 10/h |
| 1 | 7-13d | 6 | 20 | 120/h | 20/h |
| 2 | 14-20d | 12 | 40 | 240/h | 40/h |
| 3 | 21-27d | 24 | 80 | 480/h | 80/h |
| 4 | 28-34d | 48 | 160 | 960/h | 160/h |
| 5 (uncapped) | 35d+ | no limit | no limit | no limit | no limit |

Age alone is necessary but not sufficient — the identity MUST also have at least `tier * 2` participation records from distinct contexts (not self-created) to advance. This prevents aging-only sybil attacks where an attacker creates identities and waits without interacting.

**Enforcement:** Earned capacity is enforced at the SDK level. The SDK tracks the identity's creation timestamp (from the identity's inception event), participation record count (from context state), and inactivity duration. Rate limit violations produce `ErrorCode::RATE_LIMITED` (error code 4001) with a `Retry-After` hint. Context governance MAY impose stricter thresholds than the protocol defaults (§9.3 layer 3), but MUST NOT relax them below the protocol floor for identities at tier 0-2.

Sybil resistance is a **deterrent**, not an enforcement guarantee. The defense is structural: expensive to mount, expensive to sustain, costly when detected.

## 9.4 Systemic Defense Philosophy

Static rules cannot permanently defeat emergent threats. The protocol's role is to maximize the surface area of what can be independently verified, and to make whatever remains legible enough for agents and governance to respond.

Key principles:

**Validate, minimize trust.** Every claim that can be mechanically verified should be. The four-layer trust model (§7.1) prioritizes protocol enforcement and participation validation over attestation authenticity and subjective trust. The trust surface shrinks as the network accumulates history.

**Don't inspect content, inspect behavior topology.** Monitor structural metadata — growth rates, bridge activity patterns, context creation velocity, invitation patterns, outlet invocation anomalies, governance action frequency — not what's being said. The protocol equivalent of metabolic signals, not thoughts.

**Consequences over character.** Where possible, replace "trust that actors will behave" with "verify that misbehavior is irrational given the consequences." Automated consequence mechanisms (§7.3.7) make participation boundaries mechanical rather than discretionary.

**Observability is the immune system.** The protocol provides verifiable event logs, participation records, outlet verification results, challenge-response outcomes, and attestation freshness data. These are the immune system's sensory apparatus. The actual immune response is an evolving network of agents and governance tools that consume this data and get better over time.

### 9.4.1 Isolation Boundaries Enforced by Construction

Wherever possible, isolation boundaries SHOULD be enforced by the language's visibility or type-checking rules rather than by documentation or external lint checks. Construction-time enforcement survives refactoring, aliased imports, and re-exports; after-the-fact checks are weaker and must be actively maintained.

Specific isolation boundaries in the runtime:

- **Per-context state ownership.** A context's state is owned by exactly one computation and is not shareable. Handler code mutates state only through the owning computation. No mechanism exposes one context's state to another context's handler.
- **Cross-identity capability restriction.** Operations that read per-identity state (wrapping keys, KeyPackage pool, recovery state) are reachable only via a capability proof that identifies the requesting identity. The capability proof is issued at actor construction and cannot be constructed or copied by handler code. An operation executing in an actor owned by identity `A` can read only `A`'s per-identity state; any read of another identity's state requires a saga (§5.15.4).
- **Capability is unduplicable, unforgeable, and opaque.** The capability proof MUST satisfy all of:
  1. **Not duplicable.** No API, trait, impl, or ergonomic conversion returns a copy, clone, or alternative instance of the proof. Language-specific: Rust impls MUST NOT derive or implement `Clone`, `Copy`, `Serialize`, `Deserialize`, `Default`, `Hash`, `PartialEq`, `Eq`, `Borrow`, or `From`/`Into` for the capability type; other languages MUST apply the equivalent set of restrictions. A `&self`-only reissue method taking no raw identity input is permitted — it duplicates a proof the caller already holds without broadening which identities are reachable, so it is not a forgery surface (see ADR-049 §5). Language-specific (Rust): the visibility of that reissue method, and of any read-only `&DID` accessor of the token's own owning identity, MUST be exactly `pub(in crate::context)`, never `pub` or `pub(crate)`.
  2. **Not inspectable.** No API (including any `Debug`, `Display`, `Deref`, `AsRef`, or equivalent accessor) returns the inner DID or its bytes in a form that allows reconstruction of the proof or its use as a lookup key elsewhere. The proof is opaque to handler code; only supervisor-module code consumes it. A borrowed `&DID` accessor (e.g. `as_did`) returning a read-only reference to the token's own owning identity is permitted: it cannot reconstruct or forge the proof (there is no `From<&DID>` and no public constructor) and exposes only the actor's own DID, never a key into another identity's state. Language-specific (Rust): such an accessor's visibility MUST be exactly `pub(in crate::context)`, the same bound as the reissue method above.
  3. **Not forgeable.** The proof's constructor MUST be visible only to the supervisor module that issues it. Unsafe escapes (raw-pointer conversion, transmute, reflection-based instantiation) MUST be explicitly forbidden in the module that defines the capability.
  4. **Not leak-prone.** No reachable field on any type bound to handler code stores the proof by value, by clone, by shared reference beyond its originating call, or by serialized representation.
  Implementations MUST enforce these properties mechanically by the language and compiler — not by a bespoke external scanner. Language-specific (Rust): this means the constructor's restricted visibility, the capability type's private field (no external struct-literal construction), and the module lints `#![deny(unsafe_code)]` (blocking transmute/unsafe-`Send` fabrication) and `#![deny(non_local_definitions)]` (blocking a nested `impl` of the capability type smuggled into a function body — a second in-module minter). Other languages MUST enforce the equivalent properties through their own type system and compiler. A separate source-text CI scanner is not required and SHOULD be avoided: its only residual threat is an insider editing the capability's defining file, who could equally edit the scanner, so it adds no marginal security over the compiler-enforced constraints plus code review of the (small, frozen) definition. One sub-property is *not* compiler-assertable and is therefore REVIEW-enforced: the exact `pub(in crate::context)` visibility mandated for the reissue method and the `&DID` accessor above. Rust visibility is not mechanically checkable at compile time the way a missing derive is (a widen to `pub(crate)`/`pub` still compiles), so this exact-visibility MUST is a visible-diff invariant owned by code review of the frozen definition — consistent with the three-layer model (type system, compiler lints, review), with this clause squarely in review's layer.
- **No API returns per-identity state given an arbitrary DID.** The only supervisor API that returns per-identity state takes the capability proof as a parameter. Callers cannot pass another identity's DID and receive that identity's state.

### 9.4.2 Authorization-State Persistence Invariant

Any operation that transitions a member's authorization **downward** MUST be synchronously persisted before the operation is visible to any observer as defined in §5.15.3. A process crash between the mutation and the acknowledgment MUST NOT restore the pre-mutation authorization.

Operations covered (downward transitions — those that reduce or remove authority):

- UCAN attenuation, expiration enforcement, revocation (NOT issuance — see note below)
- Role demotion, role revocation, blocklist additions, broadcast author block
- Broadcast per-author **subscriber block** and **governance subscriber ban** (§5.14.8): each advances the per-author broadcast key epoch and adds the target DID to a block list (the ban to ALL authors' block lists, plus registry removal), revoking future key access — sync-persisted fail-closed, atomic with `read_exclusion_list`. The UNBLOCK / `RestoreAccess` direction is upward and MAY be coalesced.
- Content-access key revocation, sender-key destruction on block (all three tiers of §9.16 enforcement)
- MLS member removal
- Capability suspension and standing downgrades (including cooldown activation that forecloses previously-authorized action)
- Governance timeout expiry that transitions an active proposal into a denied or lapsed terminal state
- Wrapping-key rotation (forward-secrecy class)

**UCAN issuance note.** Issuance grants authority and is therefore not itself downward. It is listed in §5.15.3 as sync-persisted for a distinct reason: a caller's acknowledgment of "the token was issued" that rolls back would leave a non-existent token that the caller believes to hold. For the §9.4.2 security invariant, only the downward transitions above are load-bearing; issuance's sync-persistence is a caller-consistency concern.

Coalesced persistence (§5.15.3) MUST NOT be used for any downward transition above. Rollback from a coalesced crash would re-grant authority that was meant to be removed, creating a window where a revoked or suspended attacker can replay actions.

The full list of sync-persisted operations (which is a superset of the downward-transition set above) is enumerated in §5.15.3.

### 9.4.3 Saga Journal Secret Handling

The cross-context saga coordinator writes phase transitions to a durable journal (§5.15.4, §17.16). Saga evidence carried in journal entries is classified as **secret-bearing** or **public**. Bearer artifacts (unrevoked proof tokens that would authorize action on their own; any future evidence that carries usable secret material) are secret-bearing; plan-level metadata and public identifiers are not.

**No saga is secret-bearing today.** **The single defined saga** — cross-context outlet invocation (§6.2.4) — is public-metadata-only: its journal and envelopes carry no bearer material (the outlet invocation carries a UCAN *index*, not the token). (Standing-pair creation is **not** a saga and journals nothing — it is single-context async creation, §5.15.8.) This section is therefore the **contract any *future* secret-bearing saga MUST satisfy**, currently with **no instance**. The requirements below are normative for any such future saga.

**Commitment construction.** Secret-bearing sagas MUST journal only a commitment — never the bearer bytes. The commitment is constructed as:

```
commitment = SHA-256(domain_separator ‖ bearer_envelope ‖ nonce)
```

where:

- `domain_separator` is a fixed, per-saga-type byte string of at least 16 bytes, unique across saga types and distinct from any other protocol hash domain (e.g., `"scp/saga-commit/<saga-type>/v1"` for the future saga type). It MUST be registered in the §9.18.2 Domain Separators table when such a saga is introduced.
- `bearer_envelope` is the canonical serialization of the bearer artifact (deterministic; two conforming implementations produce byte-identical envelopes for equivalent inputs).
- `nonce` is a freshly sampled 32-byte value from a cryptographically secure random source (OsRng or equivalent). The nonce is distinct per saga instance; nonce reuse is a protocol violation.

SHA-256 is the only approved hash for this construction. The commitment is binding (no two distinct bearers produce the same commitment within computational bounds of SHA-256) and hiding (no bearer can be recovered from the commitment alone).

**Bearer handling in memory.** The bearer remains in actor-local state. Bearer bytes MUST be stored in a wrapper that zeroizes on drop, is never cloneable, never serializable, never renderable via any debug or display accessor, and never printable via any formatter. Any function that receives the bearer by value MUST zeroize it before returning, even on panic, cancellation, or early error return. Language-specific: Rust implementations MUST use `Zeroizing`-wrapped storage with no `Clone`/`Debug`/`Display`/`Serialize`/`Deserialize` on the containing type; other languages MUST apply the equivalent set of restrictions. Implementations MUST enforce this discipline mechanically by the language and compiler wherever the property is expressible — the `Zeroizing` wrapper plus the *absence* of `Clone`/`Copy`/`Debug`/`Display`/`Serialize`/`Deserialize` impls (enforced by missing-impl compile errors and `deny`-able lints) — and by code review for any residual the type system cannot express (e.g. zeroize-on-drop ordering, or zeroization on panic/cancellation/early-return paths). A bespoke source-text scanner is not required and SHOULD be avoided (per §9.4.1); any residual mechanical check MUST be justified against the §9.4.1 bar — that it constrains an attacker who cannot equally edit the check — and not asserted by analogy. Note the honest asymmetry with the capability proof: the bearer carries secret *bytes*, so its discipline is *less* fully compiler-expressible than the sole-minter property of §9.4.1 (which the type system enforces outright). If a genuine residual escapes the type system — a byte-handling discipline the language cannot encode — that is the one place a narrow, definition-scoped check could still earn its keep, justified on its own merits rather than by analogy to a property the compiler already guarantees.

**Journal entry handling at rest.** In-memory journal entries MUST be zeroized on drop. Storage backends for the journal MUST declare an at-rest encryption posture. Backends without at-rest encryption MUST refuse to host secret-bearing saga types; the runtime's journal construction fails closed against mismatched backends. Marking a secret-bearing saga resolved MUST synchronously overwrite the on-disk evidence bytes before the operation returns, not at next compaction.

### 9.4.4 Construction-time enforcement of §9.4 invariants in the SCP runtime

The §9.4 invariants — per-context state ownership, cross-identity capability restriction, the authorization-state persistence rule, and the saga journal secret-handling policy — are enforced **by construction** in the SCP reference runtime per [ADR-049 §1, §5, §9](../adrs/ADR-049-actor-per-context.md) (actor-per-context) rather than by review discipline.

The actor model collapses lock-ordering and TOCTOU concerns into per-context single-task ownership: a context's state is owned by exactly one tokio task that holds `&mut PerContextState` by move. Cross-identity reads route through `SupervisorHandle` methods that take `&OwnedIdentityDid`, a capability proof issued at actor spawn time and unconstructable from handler code. The lock-free read invariant ([ADR-049 §Decision 12](../adrs/ADR-049-actor-per-context.md#12-lock-free-read-invariant)) keeps the read path off `RwLock` so per-acquire cost cannot accumulate into a denial-of-service surface. The per-saga-phase journal write satisfies §9.4.3's "synchronous overwrite on terminal resolution" requirement.

Implementers retargeting another runtime to SCP MAY use a different concurrency primitive (mutex-per-context, single-threaded event loop, etc.) provided each §9.4 invariant remains enforced — by construction or by an equivalent mechanical check. Retrofitting these guarantees as discipline rules has been observed to fail in practice (see ADR-049 §Context for the SCP runtime's pre-refactor experience); ADR-049 §Decision 1 documents the choice to pay the one-time refactor cost rather than maintain ongoing review burden.

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

The Merkle root provides tamper-evident integrity over the entire event history. Inclusion proofs (proving a specific event is in the log) require `O(log N)` hashes. Consistency proofs (proving one log state is a prefix-extension of a *later state of the same log*) also require `O(log N)` hashes. These are used for **same-log catch-up integrity** during sync reconciliation (§23.7): a member fetching missed events verifies that the relay did not rewrite history — its older root is a prefix of the newer root. Consistency proofs are **NOT** used for cross-member equivocation detection (§9.9.3): different members hold different logs, so equivocation is detected by **Merkle-root equality at the same event count** and resolved with **inclusion** proofs for the conflicting events, not consistency proofs.

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
- **u8 integers:** 1 byte (no endianness — a single octet).
- **Fixed-length bytes of other sizes** (`[u8; 16]`): raw bytes, no length prefix.
- **Repeated fields** (a list of elements of one type — a root set, a next set, a commitment list, a signer index list): a 4-byte big-endian element count, then each element encoded by its own rule above, in list order. The count makes two adjacent lists of fixed-length elements re-parse to one reading, so a preimage carrying two such lists is injective in their boundary.
- **Optional fields:** if present, encoded by the rule its type takes above. **If absent, the sentinel is the 32 bytes `SHA-256(0x00)`, encoded by the same rule the present form takes** — one encoding, no second reading:
  - a field whose present form is **variable-length** (a 4-byte big-endian length prefix and the bytes) encodes an absent value as `00 00 00 20` followed by the 32 sentinel bytes;
  - a field whose present form is **fixed-length** (raw bytes, no length prefix) encodes an absent value as the 32 sentinel bytes bare.

  The sentinel is distinguishable from any real hash because `SHA-256(0x00)` is not a valid hash of structured data with a domain separator. Every cell of §9.5.2 that carries an optional field writes the absent bytes literally, so no binding has to derive them from this rule.

**Field ordering** is defined per struct and is part of the protocol specification. Changing the field order changes the hash. Fields are listed in the order specified below for each struct.

**Domain separator versioning:** each struct's domain separator includes a version suffix (e.g., `"SCP-INNER-ENVELOPE-V1:"`). Changing any field's encoding, adding a field, or removing a field requires incrementing the version. Old signatures become invalid — this is intentional.

**Reference implementation:** the key-continuity fingerprint (§9.11, `"SCP-KEY-CONTINUITY-V1:"`) uses this exact construction and enumerates every field in place — no length prefix on the fixed-length 32-byte identifiers and keys, and a 4-byte count on each root-set member list under the repeated-field rule; the key-event signature preimage uses the same construction under `"SCP-KEL-EVENT-V1:"` (§9.7.4.2 R13), and it carries every repeated field under the count-prefixed rule above. The order in which those fields sit in that preimage is fixed in a later revision of §9.7.4.2, which also fixes the identifier's textual form.

**Additional signed structures** using this canonical hash construction are defined in their respective spec sections: `ResetRequest` (domain: `"SCP-RESET-REQUEST-V1:"`) is defined in §23.5.2, and the **service record** (domain: `"SCP-SERVICE-RECORD-V1:"`) is defined in `03-identity.md` §3.10.13.

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
| 10 | `provenance_hash` | 4-byte BE length + 32 bytes; absent = `00 00 00 20` followed by the 32 bytes `SHA-256(0x00)` |
| 11 | `signing_key_id` | 4-byte BE length + UTF-8 bytes |

Note: `version` (position 1) commits the protocol version to the signature. `message_type` (position 2) is a discriminator byte that prevents type-flipping attacks where an adversary replays a message under different type semantics (#290). `signing_key_id` is last (position 11) to match the existing implementation. It binds the signature to the verification method the signer names (`#active`), preventing key confusion attacks.

The outer envelope is unsigned — it contains only the routing pseudonym, recipient hint, blob TTL, and encrypted blob (§9.10.2). The full signature lives inside the encrypted payload, signed by the sender's Active Signing Key (`#active`), the one operational key the sender's key state names. The domain separator prevents cross-protocol hash confusion. Field-swapping attacks (e.g., moving a payload from one context to another) produce invalid signatures. Relay operators cannot verify signatures (they cannot see sender DIDs) — verification is the responsibility of context members who can decrypt the payload.

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
| 8 | `provenance_hash` | 32 bytes, no length prefix (SHA-256 of serialized provenance); absent = the 32 bytes `SHA-256(0x00)` bare |

Note: the current implementation uses AEAD authentication only; the full signed structure above is the target format. The `BroadcastEnvelope` struct will be expanded to include all fields per #352.

The AEAD nonce is intentionally excluded from the canonical hash. The AEAD authentication tag already authenticates the nonce as part of the encryption — including it in the signed hash would be redundant and would create a second binding that must be kept consistent without providing additional security.

Subscribers verify the signature against the author's Active Signing Key (`#active`), which they resolve from the author's key state.

**SenderKeyEpochAdvance** — domain: `"SCP-EPOCH-ADVANCE-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 2 | `sender_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `"key_epoch"` | literal ASCII bytes (domain separation within the hash) |
| 4 | `epoch` | 8-byte BE u64 |
| 5 | `signer_key_ref` | 4-byte BE length + UTF-8 bytes (`#active`, prevents key confusion) |

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
| 5 | `claim` | 4-byte BE length + UTF-8 bytes (RFC 8785 canonical JSON — see note) |
| 6 | `evidence` | 4-byte BE length + raw bytes if present; absent = `00 00 00 20` followed by the 32 bytes `SHA-256(0x00)` |
| 7 | `issued_at` | 8-byte BE u64 |
| 8 | `expires_at` | 8-byte BE u64 if present (a fixed-length field, no prefix); absent = the 32 bytes `SHA-256(0x00)` bare |
| 9 | `revocation_status` | 4-byte BE length + MessagePack bytes of `RevocationStatus` enum |

Note: the `claim` field is serialized as **canonical JSON per RFC 8785 (JCS)** — compact form with no insignificant whitespace and object keys sorted deterministically. The serialization is byte-identical across all conforming implementations, including for nested objects; this is the same formal canonicalization standard cited for `GovernanceProposal` `action_bytes` below. **Numeric constraint (I-JSON, RFC 7493):** numeric values within `claim` MUST be within the IEEE-754 double-precision exactly-representable integer range (|n| ≤ 2^53); larger identifiers (e.g. 64-bit snowflake IDs) MUST be string-encoded. Rationale: RFC 8785 serializes numbers as ES6 doubles, so integer values beyond 2^53 are not injective — distinct values within one rounding class canonicalize to identical bytes, and a signature over one such claim validly covers every other claim in that class. The `evidence` field, when present, is serialized as MessagePack bytes of the `AttestationEvidence` struct. The `revocation_status` field is always present (never absent) — `Active` serializes as a distinct MessagePack value from `Revoked{...}`. Including `revocation_status` in the signed scope prevents an intermediary from flipping Active↔Revoked without invalidating the signature (§7.4.1).

**KeyPackageAttestation** — domain: `"SCP-KEYPACKAGE-ATTESTATION-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `did` | 4-byte BE length + UTF-8 bytes (the attested DID; MUST equal the leaf's `ScpCredential.did`) |
| 2 | `leaf_signature_key` | 32 bytes (raw Ed25519 public key — the MLS leaf `signature_key` being bound; the Ed25519 key that self-signs the LeafNode, distinct from the three X25519 HPKE keys below) |
| 3 | `leaf_encryption_key` | 32 bytes (raw X25519 public key — the LeafNode `encryption_key`, the **ratchet-tree** HPKE key that receives path secrets; RFC 9420 §7.2. Distinct from `init_key` below) |
| 4 | `init_key` | 32 bytes (raw X25519 public key — the KeyPackage `init_key`, the HPKE key the Welcome's `EncryptedGroupSecrets` is sealed to at join; RFC 9420 §7.1. **`init_key != encryption_key`** on a KeyPackage — a distinct key, present only in the KeyPackage, single-use, consumed at join, never in the ratchet tree. Distinctness is a **KeyPackage-only** property: a bare LeafNode created without a KeyPackage — the group creator's leaf and every PCS-Update leaf (§9.7.1) — has exactly one HPKE key, its `encryption_key`, and no separate `init_key`; on such a leaf this field therefore carries `leaf_encryption_key`. The Add-time checks (§9.7.1 checks 7–8) do **not** apply to those leaves because they are **structurally** never admitted through an Add/Welcome — they enter via group creation or a Commit-borne Update — NOT because of that field-value equality. A verifier MUST NOT use `init_key == leaf_encryption_key` as a signal to skip the Add-time checks: those checks are gated by the handshake structure (every Add carries a KeyPackage `init_key`, RFC 9420 §7.1), never by an attestation field comparison (§9.7.1)) |
| 5 | `wrapping_key` | 32 bytes (raw X25519 public key — the value of the `scp_wrapping_key` (`0xFF01`) LeafNode extension, the §9.16 per-sender-key wrapping HPKE key; distinct from both HPKE keys above) |
| 6 | `signing_key_id` | 4-byte BE length + UTF-8 bytes (`#active` — the verification method that signed this attestation) |
| 7 | `issued_at` | 8-byte BE u64 (Unix seconds; equals the leaf's `Lifetime.not_before`) |
| 8 | `expires_at` | 8-byte BE u64 (Unix seconds; equals the leaf's `Lifetime.not_after`) |

Note: the `KeyPackageAttestation` binds **all four** of the leaf's own public keys to the member's `did` (field 1), and is signed by the DID verification method named in `signing_key_id` (field 6, `#active` — never a root member). The attestation must vouch for the *whole* leaf, not a subset of its keys — each of the leaf's HPKE public keys is a distinct decryption capability, and any key left unbound is one an attacker who holds only the leaf **signing** key can substitute with a key of their own:

- **`leaf_signature_key`** (field 2, raw 32-byte Ed25519) — the ephemeral MLS leaf `signature_key` that self-signs the LeafNode.
- **`leaf_encryption_key`** (field 3, raw 32-byte X25519) — the LeafNode **ratchet-tree** `encryption_key` (RFC 9420 §7.2), which receives HPKE-sealed path secrets on Commits. Binding it stops a stolen `signature_key` from being paired with an attacker-chosen ratchet-tree key that would let the attacker decrypt path secrets and read post-Add traffic.
- **`init_key`** (field 4, raw 32-byte X25519) — the KeyPackage **`init_key`** (RFC 9420 §7.1), a key DISTINCT from `encryption_key`: the Welcome's `EncryptedGroupSecrets` is HPKE-sealed to the `init_key`, not the `encryption_key`. This is the **read-as-victim-at-join** vector, and the reason binding only `signature_key` + `encryption_key` is insufficient: a thief holding only the leaf signing key could craft a KeyPackage carrying the victim's `signature_key`, the victim's *public* `encryption_key` (passing that check), a genuine copied attestation — and an **attacker-chosen `init_key`**. The adder would then seal the Welcome to the attacker's `init_key`, and the attacker would decrypt the group secrets and read as the victim. Binding `init_key` closes this. Because the `init_key` lives ONLY in the KeyPackage (it is consumed at join and is NOT part of the ratchet tree), the verifier checks it **only at Add/Welcome time**, where the adder holds the full KeyPackage — see §9.7.1 (it is correctly not re-checked on later Commit/Proposal verification, because the read-as-victim attack lands at join).
- **`wrapping_key`** (field 5, raw 32-byte X25519) — the value of the leaf's `scp_wrapping_key` (`0xFF01`) extension, the §9.16 per-sender-key wrapping HPKE key. Without binding it, a `signature_key` thief substitutes their own wrapping key and harvests other members' §9.16 sender keys distributed to the victim. Like `signature_key`/`encryption_key`, it is present on every leaf and is checked on both triggers — Add and Update (leaf introduction or change), not on a Commit that leaves the committer's leaf unchanged (§9.7.1 "Verification (MUST) — when it runs").

`encryption_key`, `init_key`, and `wrapping_key` are three **distinct** X25519 HPKE keys serving three distinct roles (ratchet-tree path secrets, Welcome seal, sender-key wrapping); the attestation binds each so none can be swapped for an attacker key. The attestation is deliberately **context-agnostic**: it carries no `context_id`. A KeyPackage is a per-identity, pre-published pre-key bundle that must be mintable offline — before any group it will be added to is known — so a context scope is unknowable at mint time; group-scope binding is provided separately and redundantly by the `scp_context_params` GroupContext extension (`0xFF02`, §5.13.3), which binds the leaf's actual group. The signature covers the §9.5.1 canonical hash of the eight fields above under the `"SCP-KEYPACKAGE-ATTESTATION-V1:"` domain separator. The attestation is carried in the MLS leaf as the `scp_keypackage_attestation` LeafNode extension (§9.18.7) and is re-issued on leaf-key rotation (§9.7.3). Verifiers resolve the `signing_key_id` verification method from the signer's **current** key state (§9.6.1) and check this signature; a leaf whose attestation does not verify — or whose `leaf_signature_key`, `leaf_encryption_key`, or `wrapping_key` does not match the leaf's actual keys, or whose `init_key` (at Add time) does not match the KeyPackage `init_key`, or whose `did` does not match the credential — MUST be rejected (fail-closed) per the §9.7.1 verifier rules. This structure is the direct analog of `IdentityLinkAttestation` (§3.5.2): a `#active`-signed statement binding an identity to an out-of-band fact, verified against the signer's current key state.

**`scp_keypackage_attestation` (`0xFF03`) LeafNode extension body.** The extension body is a **deterministic length-prefixed binary serialization** — explicitly NOT MessagePack or JCS — chosen so that all four bindings (native, wasm, UniFFI, NAPI) produce byte-identical extension bytes. It is the eight attestation fields, **in the same order as the signed preimage above**, followed by the raw 64-byte Ed25519 signature:

```
BE32(len(did)) || did
  || leaf_signature_key                       (32 raw bytes, no length prefix)
  || leaf_encryption_key                      (32 raw bytes, no length prefix)
  || init_key                                 (32 raw bytes, no length prefix)
  || wrapping_key                             (32 raw bytes, no length prefix)
  || BE32(len(signing_key_id)) || signing_key_id
  || issued_at                                (8-byte BE u64)
  || expires_at                               (8-byte BE u64)
  || signature                                (64 raw bytes)
```

The variable-length fields (`did`, `signing_key_id`) carry a 4-byte big-endian length prefix; `leaf_signature_key` is the raw 32-byte Ed25519 public key and `leaf_encryption_key`, `init_key`, and `wrapping_key` are each a raw 32-byte X25519 public key (all fixed-length, no length prefix); `issued_at`/`expires_at` are 8-byte big-endian unsigned integers; the trailing 64 bytes are the raw Ed25519 signature over the §9.5.1 canonical hash (the domain separator appears only in the signed preimage, never in the extension body). This mirrors how the `scp_wrapping_key` (`0xFF01`) LeafNode extension carries its raw X25519 public key. A byte-exact known-answer vector is in §25.23 (Vector 37).

**ParticipationProfile** — domain: `"SCP-PARTICIPATION-PROFILE-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `subject_did` | 4-byte BE length + UTF-8 bytes |
| 2 | `signer_public_key` | 32 bytes |
| 3 | `participation_duration_secs` | 8-byte BE u64 |
| 4 | `governance_actions_against` | 8-byte BE u64 |
| 5 | `governance_actions_by` | 8-byte BE u64 |
| 6 | `outlet_invocation_count` | 8-byte BE u64 |
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
| 4 | `signing_key_id` | 4-byte BE length + UTF-8 bytes (`"#active"`) |
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

Note: The `ProposalId` is the SHA-256 output (32 bytes). It is deterministic for identical inputs and collision-resistant across contexts. The `action_bytes` field uses **canonical JSON** serialization of the `GovernanceAction` enum (externally tagged, compact format with no whitespace — equivalent to `json.dumps(separators=(',', ':'))` in Python). JSON is used rather than MessagePack because `GovernanceAction` is a complex 30-variant enum whose serialized form must be byte-identical across all SDK implementations. MessagePack has no canonical form standard and field ordering varies by library; JSON serialization is more predictable across languages and has RFC 8785 (JCS) as a formal canonicalization standard. This is consistent with all other cross-implementation canonical hashing in the protocol: handle outlet signing (§22), app declarations (§8.4), and governance config hashing for multi-parent contexts (§5.13).

**SignedVote** — domain: `"SCP-VOTE-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `proposal_id` | 32 bytes (fixed-size, the `ProposalId` hash) |
| 2 | `voter_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `vote_type` | 4-byte BE length + JSON serialization of `VoteType` (compact, no whitespace) |
| 4 | `timestamp` | 8-byte BE u64 |

Note: The Ed25519 signature is over `SHA-256("SCP-VOTE-V1:" || fields)`. The `proposal_id` binds the vote to a specific proposal, preventing cross-proposal replay. `VoteType` is serialized as compact JSON (equivalent to `json.dumps(separators=(',', ':'))` in Python).

**KeyDestructionAttestation** — domain: `"SCP-KEY-DESTRUCTION-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 2 | `member_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `destroyed_at` | 8-byte BE u64 |
| 4 | `key_state_head` | 32 bytes, no length prefix; §9.7.1's log-anchored row constructs the value and this cell restates none of it |
| 5 | `method` | 1-byte U8 discriminator (0x00=SoftwareOnly, 0x01=HardwareBacked) |
| 6 | `platform_attestation` | 4-byte BE length + raw platform bytes; length 0 when the signer supplies none |

Note: the preimage binds `key_state_head`, which is what makes this structure the log-anchored evidence class of §9.7.1 rather than the attestation class. A verifier that read an unsigned `key_state_head` would take the anchoring position from the signer, so the field is inside the signed preimage. §9.15 states the structure's field semantics and the limit the class carries for a key the state lists retired with a compromise position.

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

### 9.6.1 The log authenticates the record

An inception-derived identifier is **self-certifying through its key-event log**: the identifier is the digest of the inception event's signed preimage (§9.7.4.2 R13), and it encodes no key. The key-event record a resolver fetches carries that log, and the log is what authenticates the record.

**One record form, and the SCP relay network carries it.** A key-event record carries the log itself: the `value` of an identity's relay record carries the chain from the inception event to the chain's head, or — when the resolver already holds a state-carrying event on that chain — the segment from that event forward (§9.7.4.2 R9 states how a relay serves a chain too long for one frame). A publisher that cannot tell what a resolver holds publishes from inception, which is the form every first-contact resolution reads. The protocol runs no second publication or resolution layer beside the relay network, and it uses no distributed hash table.

**How a resolver authenticates a served record.** When resolving an identifier:

1. The client queries every relay it knows for the record at the identifier's routing ID: the relays the identity's service record names (`03-identity.md` §3.10.13), and the community relays of the fallback set (definitions; `18-addressability-and-deployment.md` §18.5.1). A client that holds no accepted baseline for the identifier obtains the chain from two relays under distinct declared operators, at least one of them in the fallback set (§9.7.4.2 R11).
2. The client recomputes the identifier from the served chain's inception event and rejects a chain whose recomputed identifier differs from the identifier it is resolving (§9.7.4.2 R2).
3. The client verifies every event of that chain under §9.7.4.2 R3 — each indexed signature against the key at its index, each reveal against the standing commitment — and settles two chains that diverge by the fork-precedence rule (§9.7.4.2 R6).
4. The client derives the key state from the latest state-carrying event of the chain it adopted (§9.7.4.2 R8). Resolution yields key state and nothing else; the identity's transport and service metadata rides in a separate service record the client resolves on its own terms (`03-identity.md` §3.10.13), and no DID document is an output of this procedure — ADR-063 defers the `did:scp` facade and builds none.

The client reads no key from the frame that carried the record (§9.10.12). No trusted third party is required, and no key needs to be known before the resolution starts: the identifier and the inception event are the whole trust root.

**The record carries no signature of its own.** A key-event record frame carries a version, the identifier, and the `value` that holds the chain (§9.10.12), and nothing authenticates the frame beside the chain inside it. A relay's write decision is chain verification under §9.7.4.2 R2 and R3 plus the slot rule of §9.7.4.2 R9 (`03-identity.md` §3.10.2 states the procedure), and a resolver's trust decision reads the log under steps 2 through 4 above. A signature over the frame would be checked against a key the verifier reads out of the writer's own chain, so it would authorize nothing that chain verification has not already authorized.

**MITM on resolution is impossible given the correct identifier.** A relay cannot serve a fraudulent chain under an identifier it does not control, because step 2 recomputes the identifier from the inception event the chain carries and a different inception event yields a different identifier. Tampering is detectable without trusting any intermediary.

**Stale record prevention:** the frame carries no sequence number, and a relay appends a frame's events to the chain it holds and replaces none of them (§9.7.4.2 R9; `03-identity.md` §3.10.2 states the procedure). The client discards, without changing its accepted state, a candidate whose chain is a head of the accepted chain at a sequence strictly lower than the highest it has accepted (§9.7.4.2 R12). Two key-event chains that diverge from a shared prefix are not comparable by sequence, and a client settles them by the fork-precedence rule of §9.7.4.2 R6, which may adopt a chain whose head sequence is lower than the head the client previously held (§9.7.4.2 R12).

**The remaining question:** "Is this the right identifier?" The identifier↔inception binding proves that a chain belongs to an identifier, but cannot prove the binding between an identifier and a person. This is an out-of-band verification problem addressed by Key Continuity Verification (§9.11).

**No relay is trusted.** The log authenticates the record under §9.7.4.2 R2 and R3, so a resolver's integrity guarantee never rests on which relay served the record. Freshness at first contact comes from the two distinctly-operated relays R11 requires; freshness afterwards comes from the accepted baseline R12 holds against a candidate, and, once the witness protocol is specified, from the cosigned heads of the witness layer.

### 9.6.3 Relay List Authentication

An identity's relay list rides in its **service record**, the second owner-signed resolvable that `03-identity.md` §3.10.13 defines and owns. This section states how a client authenticates that list; §3.10.13 states what else the record carries, who signs it, and how a resolver settles two copies.

**For an inception-derived identifier:** the client verifies the service record's signature against the operational key the identity's latest state-carrying key event designates for the service-record role (§9.7.4.2 definitions), and it verifies that key event under §9.7.4.2 R2 and R3 before it reads the designation. Two verifications chain: the log authenticates the designated key, and the designated key authenticates the relay list. Substituting a relay list therefore requires the designated key, and substituting the designation requires a threshold of the identity's standing root. The key-event log itself carries no relay list.

**For transport adapters with native relay lists:** Some transport adapters (e.g., Nostr via NIP-65) publish relay lists in transport-specific formats signed by a keypair derived from the identity's key material. This provides relay list authentication independent of the identity method but is adapter-specific, not a protocol requirement.

**Attack: relay list substitution.** A compromised relay could serve a stale service record, directing messages to relays the recipient no longer uses. Defense: a client takes the relay list from the highest-sequence service record whose signature verifies against the designated key, and it rejects a record at a sequence lower than the highest it has already accepted for that identity (§3.10.13). A relay that holds the designated key's signature over no newer record cannot manufacture one.

### 9.6.4 First-Contact Trust Bootstrapping

When Alice first encounters Bob's DID (via shared context membership, registry discovery, or referral):

- **For an inception-derived identifier:** Alice obtains the key-event log, recomputes the identifier from the inception event (§9.7.4.2 R2, R13), and derives the key state from the latest state-carrying event (R8). The identifier↔inception binding is cryptographically verified, and the identifier encodes no key; a relay can withhold the log but cannot substitute a chain under Alice's identifier for Bob.
- **For every identifier:** the SDK records a `ContinuityStanding` for the identifier on first contact (§9.11) and sets it `PendingReverify` on every `RootRecovery` it observes **after** that first contact, and on the events §9.11 names. A first contact applies trust-on-first-use to the chain as Alice resolved it, whatever that chain contains: a `RootRecovery` already on the chain at first contact is part of the history Alice is trusting on first use, and Alice is not observing one. **Trust-on-first-use applies only to a resolution that adopted a chain**: a first encounter whose resolution returns any verdict other than `Confirmed` or `Adopted` — `Contested`, `Inconclusive{cause}`, `Invalid{at_event}`, or `Discarded{accepted_head}` — records no root-install digest and sets the standing `PendingReverify` (§9.11). Each of those four verdicts leaves the verifier without an adopted chain, so it has no root to install as the digest a later key change is compared against; a verifier that recorded `Verified` on one of them would fix a standing against a chain it never adopted and the key-change trigger of §9.11 could never fire for that identifier.

## 9.7 Group Key Management — MLS Integration

MLS (RFC 9420) provides the group encryption layer for SCP. This section specifies how MLS concepts map to SCP and what security properties the SDK must enforce.

### 9.7.1 MLS-to-SCP Concept Mapping

| MLS Concept | SCP Concept | Notes |
|---|---|---|
| Group | Context | 1:1 mapping. Each SCP context is one MLS group. |
| Member (LeafNode) | Agent (in context) | One MLS leaf node per agent in the context. |
| Epoch | Context epoch | Increments on every membership change or key update. Included in all SCP envelopes. |
| LeafNode credential | DID + UCAN + signing_key_id | The MLS credential field contains the member's DID, their context-scoped UCAN token, and the `signing_key_id` (`#active`) identifying which verification method signed the leaf's **KeyPackage attestation** (§9.7.1) — the leaf node itself is self-signed by its own ephemeral MLS key, not by a DID key (ADR-039). |
| Welcome message | Context join token | HPKE-encrypted to new member's KeyPackage. Contains the group state needed to decrypt future messages. |
| KeyPackage | Pre-key bundle | Published to relays so others can add the identity to groups even when offline. The leaf node is self-signed by an **ephemeral, context-scoped MLS key**; a **KeyPackage attestation** carried in the leaf (LeafNode extension `scp_keypackage_attestation`) binds that ephemeral key to the DID and is signed by the Active Signing Key (`#active`) — never by a root member. Single-use. See note below. |
| Proposal (Add/Remove/Update) | Governance action | MLS membership proposals map to SCP membership changes. |
| Commit | Governance commit | Finalizes pending proposals and advances the epoch. |
| Application message | SCP envelope payload | The encrypted content within an SCP envelope. |
| Delivery Service (DS) | SCP relay(s) | The untrusted store-and-forward layer. Any transport adapter (native relay, Nostr, Matrix, etc.) serves this role. |
| Authentication Service (AS) | DID resolution + UCAN validation | SCP's identity layer serves as MLS's AS. No separate trusted server. |

**KeyPackage leaf key and DID attestation.** Per RFC 9420 §5.3, the `signature_key` in a KeyPackage's `leaf_node` field signs the leaf node itself. In SCP this is an **ephemeral, context-scoped Ed25519 key** generated by the MLS layer (`SignatureKeyPair::new()`) — it is NOT a DID verification method, and a verifier MUST NOT expect it to resolve to one. The leaf is self-signed by this ephemeral key, exactly as RFC 9420 requires. Per-message sender identity is carried separately, by the inner-envelope `#active` signature (§9.8.1), never by the MLS leaf key.

Binding the ephemeral leaf key to a DID is the job of a separate **KeyPackage attestation**: a signed statement, produced by the identity's Active Signing Key (`#active`), that binds `{ DID, leaf signature_key, leaf encryption_key, init_key, wrapping_key, signing_key_id, issued_at, expires_at }` (binding **all** of the leaf's public keys — the Ed25519 `signature_key`, and the three distinct X25519 HPKE keys: the LeafNode ratchet-tree `encryption_key`, the KeyPackage `init_key` (`init_key != encryption_key`; the Welcome is HPKE-sealed to `init_key`), and the `scp_wrapping_key` `0xFF01` `wrapping_key` — see §9.5.2 for why each is required). An attestation is minted at **every leaf-creation site — all three of them**: (1) group creation (`create_group`, where the creator's leaf is built directly with **no** published KeyPackage — the creator leaf still has a LeafNode `Lifetime`, just no `KeyPackage` wrapper), (2) add-time KeyPackage generation (the published pre-key bundle), and (3) every PCS Update, which generates a fresh ephemeral leaf key and therefore requires a fresh attestation over it (§9.7.3). In each case `issued_at`/`expires_at` are set to the leaf's own `Lifetime.not_before`/`Lifetime.not_after`, so the attestation's validity window is exactly the leaf's lifetime (this generalizes across all three sites — the creator leaf has a `Lifetime` but no `KeyPackage.Lifetime`). The `signature_key`, `encryption_key`, and `wrapping_key` bindings are present at **all three** sites (every leaf carries the `scp_wrapping_key` `0xFF01` extension and a ratchet-tree `encryption_key`). The `init_key` binding, however, is meaningful only at site (2): only a published KeyPackage has a distinct `init_key`, and only a KeyPackage leaf is admitted through an init-key-sealed Welcome. At sites (1) and (3) the leaf has no KeyPackage — its sole HPKE key is its `encryption_key` — so the attestation's `init_key` field simply carries `leaf_encryption_key` there. Verifiers never run the Add-time `init_key` checks (§9.7.1 checks 7–8) against those leaves **because such leaves are structurally never admitted through an Add/Welcome** — they enter via group creation or a Commit-borne Update — NOT because of that field-value equality; a verifier MUST NOT treat `init_key == leaf_encryption_key` as a license to skip the Add-time checks (see the Verification structural note). Its preimage follows the §9.5.1 canonical construction under the domain separator `"SCP-KEYPACKAGE-ATTESTATION-V1:"` (structure in §9.5.2). The attestation rides **in the leaf node as an MLS LeafNode extension** (`scp_keypackage_attestation`, extension type `0xFF03`, §9.18.7), mirroring the existing `scp_wrapping_key` LeafNode extension — so it is carried in the ratchet tree, is available to any verifier that reads the leaf, and is covered by the leaf's self-signature. Placing it in the leaf (rather than as a `Credential` field) is deliberate: a LeafNode extension travels with the leaf through Welcome and Commits, is committed by the leaf signature, and needs no separate distribution channel. A root member is NOT used — the root is reserved for establishment events (§9.7.4.2 definitions define the term: every key event, and only key events) and after inception never fixes a commitment alone (§9.7.4.2 R1); attestation issuance is an operational action, not an establishment event. Signing uses the identity custody `KeyCustody::sign` — a single async signature, with no raw key export, so it is compatible with hardware custody and needs no `openmls` change.

**Verification (MUST) — when it runs.** Attestation verification is triggered by **leaf introduction or change**, never by mere message arrival. A member verifies a leaf's KeyPackage attestation when — and only when — that leaf **enters or is replaced in** the group: (a) at an **Add**, the KeyPackage introducing a new member's leaf, and (b) at an **Update / Commit-with-UpdatePath**, an existing member replacing their own leaf with a fresh ephemeral key (§9.7.3). A **Commit or Proposal that does not introduce or change the committer's leaf carries no new attestation to check** — the leaf and its embedded attestation are byte-for-byte the ones already fully verified when that leaf was introduced — so the verifier **MUST NOT** re-run attestation verification, and in particular **MUST NOT** re-resolve the committer's DID, for it. Skipping it is safe (there is nothing to re-check — the attestation is unchanged and was already fully verified) and is also necessary: gating every steady-state Commit on a fresh DID resolution would let an attacker who degrades one member's DID resolution — a network partition between that member's relays and the group — get that member's Commits rejected group-wide, forking the epoch or censoring the member. The trigger is therefore leaf-change, not message-arrival.

**Verification (MUST) — the checks.** On each triggering event (an Add or an Update) the verifier MUST resolve — from the attesting identity's **current** key state (§9.6.1) — the key its `signing_key_id` role names, verify the KeyPackage attestation against it, and confirm ALL of the following. Checks 1–6 and 9–13 apply on **both** triggers (Add and Update); checks 7 and 8 — the two `init_key` checks — apply at **Add/Welcome time only** (an Update replaces a ratchet-tree leaf, which has no `init_key`). The two resolution-dependent checks — 1 and 2 — additionally carry an **Add-vs-Update failure policy** stated in each: a new member's **Add** is fail-closed on resolution failure, while an already-admitted member's **Update** falls to a bounded last-known-good grace on a transient resolution *failure* (but never on a resolution *success* that returns a rotated key); see the **Resolution failure policy** below. **The Add-time checks (7–8) are triggered by the handshake structure, NOT by any attestation field value.** A verifier MUST NOT decide whether to run checks 7–8 by comparing the attestation's `init_key` to its `leaf_encryption_key`: the Add-time checks run against **every** Add proposal — which, by RFC 9420 §7.1, always carries a KeyPackage bearing an `init_key` — and against no other message. The creator / PCS-Update carve-out (§9.5.2 field 4) is **structural**, not a field-value test: creator and Update leaves are admitted through group creation or a Commit-borne Update — **never** through an Add/Welcome — so checks 7–8 simply never run against them. Keying the carve-out on `init_key == leaf_encryption_key` would be a defect: a signing-key-only attacker could harvest a victim's genuine creator/Update attestation (whose `init_key` field legitimately equals `leaf_encryption_key`) and re-present it inside an Add carrying the attacker's own `KeyPackage.init_key`, and a verifier that skipped check 7 on the field-value match would reopen the read-as-victim vector.

1. the `signing_key_id` names the role the identity's key state lists `#active` and `current`, and resolution binds to **that current key only** — a verifier MUST NOT accept an attestation signed by a key the resolved current key state lists in any of the three conditions of §9.7.1 that are not `current`, nor by any key that key state does not list `current` in the `#active` role. (Without this, an attestation signed by a rotated-away key would still verify, and the revocation-by-rotation of §9.12 would not bite.) This current-key binding is enforced on **both** triggers, but the resolution-failure policy differs by trigger. On an **Add** it is **fail-closed** — a resolution failure rejects the join (check 2; **Resolution failure policy** below). On an already-admitted member's **Update** the success-vs-failure distinction is load-bearing: a resolution **success** that returns a **rotated-away key** (the current key state no longer lists the attesting `#active` `current`) still fails this check and the Update is **rejected** — rotation revokes exactly as on an Add — whereas a transient resolution **failure** does not hard-reject but falls to the bounded last-known-good grace of the **Resolution failure policy** below, so a key-state resolution outage cannot fork the epoch or censor an existing member. On an already-admitted member's Update the verifier re-resolves with its cache bypassed before it rejects on this check (**Resolution failure policy** below states that obligation once);
2. **current-key resolution freshness:** the key state used to satisfy check 1, derived from the identity's key-event log (§9.7.4.2 R8), MUST be no older than `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7 — 300s / 5 minutes, tied to the §9.14 clock-skew tolerance). A resolver-cache entry older than this bound MUST NOT be used for the current-key check — it MUST trigger a **fresh** resolution (on an **Add**, a resolution failure then rejects, per the **Resolution failure policy** below; on an already-admitted member's **Update**, a transient resolution failure instead falls to the bounded last-known-good grace defined there, while a resolution *success* returning a rotated key still rejects). The ≤ 5-minute freshness guarantee presupposes **rollback-resistant DID resolution** — see the **Rollback-resistance assumption** below. The §9.18.7 registry row for that constant states its relation to the §9.10.7 privacy cache TTL, and no other sentence in this spec restates it. This hard-bounds revocation latency — a retired `#active` cannot keep verifying attestations past rotation for longer than this bound (§9.12), regardless of how long the privacy cache would otherwise retain the pre-rotation document;
3. the attestation's Ed25519 signature verifies against that resolved current verification method (over the §9.5.1 canonical hash under `"SCP-KEYPACKAGE-ATTESTATION-V1:"`). On an already-admitted member's Update the verifier re-resolves with its cache bypassed before it rejects on this check (**Resolution failure policy** below states that obligation once);
4. the attestation's `leaf_signature_key` equals the leaf's actual `signature_key`;
5. the attestation's `leaf_encryption_key` equals the leaf's actual LeafNode `encryption_key` (the X25519 ratchet-tree HPKE key, RFC 9420 §7.2) — so a stolen `signature_key` cannot be paired with an attacker-chosen ratchet-tree key to decrypt path secrets (§9.5.2). **This binding — not check 8 — is what denies the read-as-victim-at-join closure:** forcing `leaf_encryption_key` to the victim's real key means a signing-key-only attacker cannot substitute a decryption key it controls, and (with check 7 forcing the KeyPackage's `init_key` to the attested value, which for a copied bare-leaf attestation is that same `leaf_encryption_key`) the Welcome's group secrets remain sealed toward a key only the victim can decrypt. Check 8 is the RFC 9420 §10.1 malformed-KeyPackage guard, not this closure;
6. the attestation's `wrapping_key` equals the value of the leaf's `scp_wrapping_key` (`0xFF01`) LeafNode extension — so a stolen `signature_key` cannot be paired with an attacker-chosen sender-key wrapping key to harvest other members' §9.16 sender keys (§9.5.2);
7. **`init_key` binding (Add/Welcome time only):** when processing an Add/join, the attestation's `init_key` equals the **KeyPackage's** `init_key` (the X25519 HPKE key the Welcome's `EncryptedGroupSecrets` is sealed to, RFC 9420 §7.1) — so a thief holding only the leaf `signature_key` cannot craft a KeyPackage that reuses the victim's `signature_key` + public `encryption_key` + copied attestation but substitutes an **attacker-chosen `init_key`**, which would seal the Welcome to the attacker and let it read as the victim. **Critical asymmetry:** `init_key` lives ONLY in the KeyPackage — it is consumed at join and is NOT part of the ratchet tree — so it can be checked ONLY at Add/Welcome time, where the adder holds the full KeyPackage. It is correctly **not** re-checked on later Commit/Proposal verification (there is no `init_key` on a ratchet-tree leaf to check against, and the read-as-victim attack lands at join, not on a later Commit). This check runs on every Add regardless of whether `init_key` happens to equal `leaf_encryption_key` (see the structural note above);
8. **`init_key != encryption_key` (Add/Welcome time only) — the RFC 9420 §10.1 malformed-KeyPackage / HPKE-key-reuse guard (defense-in-depth):** reject any Add whose KeyPackage has `init_key == encryption_key`. RFC 9420 §10.1 requires a KeyPackage's `init_key` and its LeafNode `encryption_key` to be **distinct**; a KeyPackage that reuses one key for both roles is malformed and MUST be rejected. SCP names this as an **explicit** verifier MUST — defense-in-depth — rather than depending silently on the MLS library enforcing §10.1. **This check does NOT, on its own, close the read-as-victim-at-join vector:** that closure comes from binding the decryption keys (check 5, in concert with check 7), which forces the Welcome's group secrets to seal toward the victim's key. Check 8 is the belt-and-suspenders §10.1 hygiene guard on the KeyPackage's own two HPKE keys; it additionally rejects the degenerate `init_key == encryption_key` KeyPackage a signing-key-only attacker would reach for when re-presenting a victim's copied bare-leaf attestation (whose `init_key` field equals `leaf_encryption_key`, because that leaf had no KeyPackage) inside an Add;
9. the attestation's `did` equals the DID carried in the leaf's `ScpCredential`;
10. the attestation's `signing_key_id` equals the `signing_key_id` carried in the leaf's `ScpCredential` — the credential and the attestation MUST name the **same** verification method (explicit equality, so a leaf cannot claim a credential under one key while attesting under another);
11. the attestation's `expires_at` equals the leaf's `Lifetime.not_after` **and** its `issued_at` equals the leaf's `Lifetime.not_before` — the attestation's validity window is exactly the leaf's own lifetime, not a wider self-asserted one;
12. **lifetime cap:** `expires_at - issued_at <= MAX_KEYPACKAGE_ATTESTATION_LIFETIME` (§9.18.7) — reject any attestation whose self-asserted validity window exceeds the protocol maximum, so a compromised leaf key cannot be reused indefinitely (§9.7.3, §9.12);
13. **freshness:** `issued_at < expires_at` (reject any attestation with `expires_at <= issued_at`), the attestation is unexpired at the verifier's current time, and `issued_at` is not dated further into the future than the §9.14 clock-skew tolerance (5 minutes).

It is the **attestation** that is verified against the resolved key state — never the leaf signature itself. **Fail-closed scope (positive whitelist).** Attestation verification is MANDATORY and fail-closed for **all DIDs**: a leaf whose attestation is absent, malformed, expired, or failing any check above MUST be rejected. This applies to every identity without exception, and enforcement MUST NOT be keyed on any prefix of an identifier's textual form. The **only** exemption is a narrow testing carve-out, **gated behind the `testing` feature so it is never present in shipped production artifacts**, and it keys on the test construct rather than on any identifier's textual form: an identity the `testing` feature created, whose key-event log the SDK holds locally, skips relay resolution and skips §9.7.4.2 R11's two-relay first-contact rule. The verifier still runs every check above against the locally held log, and the carve-out relaxes nothing else. No identity a shipped artifact resolves is exempt.

**Resolution failure policy — Add is fail-closed; an already-admitted member's Update gets a bounded last-known-good grace.** When the verifier cannot resolve the signer's key-event log — every relay it reached timed out, a verifier holding no accepted baseline for the signer reached fewer relays than R11's two-relay **first-contact** rule requires, or any other resolution error — the policy depends on whether the leaf's DID is a **new member** (Add) or an **already-admitted member** (Update / their own leaf-changing Commit), because the availability trade-off is opposite in the two cases. In **both** cases a resolution *success* takes precedence: a document that resolves and shows the attesting `#active` **rotated away** fails check 1 and rejects — the grace below is for resolution *failure* only, never for a successful resolution that returns a new key. **R11's two-relay floor binds a first contact only.** A verifier that holds an accepted baseline for the signer resolves against one relay, so a single relay's outage is not a resolution failure for it and never fail-closes an Add of a signer whose chain that verifier already tracks (§9.7.4.2 R11).

- **New member (Add) — fail-closed, no stale fallback.** A resolution failure on an Add is a **REJECT** (fail-closed), never accept-if-uncertain, and the verifier **MUST NOT fall back to a stale or pre-rotation cached key state**. Falling back would open a **rotation-bypass**: an attacker who can *induce* resolution failures (intermittently disrupting the reachability of the identity's relays) could pin verifiers onto a **pre-rotation** cached key state in which the retired `#active` still resolves, so old attestations continue to verify past a rotation — up to the cache TTL — defeating the revocation-by-rotation lever of §9.12. This is the cross-group **Add** path — the actual leaf-reuse threat (§9.7.3 "Scope of the PCS bound") — so it keeps the tight, fail-closed **≤ 5-min** current-key bound. Delaying a not-yet-member forks and censors nothing, so the correct availability posture is to **retry/queue the join**, not to admit on a possibly-retired key. The resolver cache is retained **only as a positive same-or-fresher optimization** for this current-key check (never as a fallback *for* a failed resolution), with a freshness TTL **no longer than `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7 — 300s / 5 min; check 2)**.
- **Already-admitted member (Update) — bounded last-known-good grace on transient failure.** An existing member replacing their own leaf is a different posture: they already passed fail-closed verification at their own Add, and their Commits carry the group forward. A `RootRecovery` for that identity does not change that posture: an existing member's Update, Commit, and Remove proposal are admitted whatever that identifier's `ContinuityStanding` is, and the replaced leaf's attestation is checked against the adopted key state exactly as check 1 always checks it. The standing gates admission and grants, never an existing member's handshake traffic (§9.11). Here, on a transient resolution **failure** (the document cannot be fetched at all), the verifier uses the member's **last-known-good** key state — the most recent one it successfully resolved — within a **bounded grace** (bounded by that document's own retention, §9.10.7, and always overridden by the next successful resolution) **instead of** hard-rejecting, so a transient DID-resolution outage cannot fork the epoch or censor an existing member (the BLACK-C22-10 liveness/censorship vector). This last-known-good retention bound (§9.10.7) holds **only under the Rollback-resistance assumption below**: a rollback-capable attacker who re-serves an equal-`seq` pre-rotation chain under *sustained* resolution failure could keep refreshing the last-known-good entry and reset its retention timer, degrading the effective grace toward `MAX_KEYPACKAGE_ATTESTATION_LIFETIME` (§9.18.7 — the 84-day backstop is the honest upper bound); the resolution-layer mitigation is the sequence rule of §9.6.1, which discards a head of the accepted chain at a sequence strictly lower than the highest the verifier has accepted (§9.7.4.2 R12). This grace applies **only** to resolution failure: a resolution **success** that returns a rotated key still rejects (see check 1). **Before rejecting an already-admitted member's Update on check 1 or check 3, the verifier MUST re-resolve that identifier's key-event log with its cache bypassed, and rejects only when the fresh resolution still fails the check.** The case that obligation closes is a resolution success against a cache-fresh pre-rotation key state: the member rotates `#active` and issues the §9.12 step-2 Update in the same minute, a peer holds a pre-rotation key state four minutes old, check 2 admits that entry because it is inside `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`, and check 3 then verifies the member's new-key signature against the retired key and fails. A resolution success reaches no grace, so without the re-resolution every planned rotation — including the custody migration of `03-identity.md` §3.2.1 case 1, which is not a compromise — forks the epoch at every peer whose cached key state is younger than the bound and fresher than the rotation. The content path carries the same obligation under **A content-signature freshness bound** below. The grace does not weaken revocation, either: revoking an already-admitted, genuinely-compromised member is a **governance Remove** (as in MLS — the standard mechanism for evicting a compromised member), not a per-commit hard reject driven by an induced resolution outage. This presupposes a **governance authority other than the compromised member**. In a **SingleAdmin** context (§5.9) where the sole admin's full MLS state is compromised, no other party can issue the Remove; that case is a **context-re-creation** event (§5.9 governance / §5.11A migration), not a grace-recoverable one — compromise of the sole governance authority is game-over for the context regardless of this mechanism. The reuse threat the tight ≤ 5-min fail-closed bound defends against is the cross-group **Add**, which this grace does not touch.

**Rollback-resistance assumption.** The ≤ 5-min freshness guarantee (check 2) presupposes **rollback-resistant key-state resolution**. An attacker who serves an **OLD but validly-signed, lower-`seq`** chain as if it were a "fresh resolution" would return a **pre-rotation** key that the freshness check cannot catch — the chain is genuinely signed, only stale, so it passes as fresh. This is out of scope for the attestation verifier; it is mitigated at the **resolution layer** — the sequence rule of §9.6.1, which rejects a head of the accepted chain at a lower sequence than the accepted head, together with chain verification, which rejects a chain that recomputes to another identifier — which the attestation verifier **assumes**, rather than re-checking as a separate attestation check.

On key rotation (§9.7.3, §9.12), it is the **attestation** that is re-issued under the new `#active` key (a fresh signature over the leaf keys), not a leaf key made equal to the rotated identity key; outstanding KeyPackages carrying an attestation signed by the old key MUST be deleted from relays and replaced. Because verifiers resolve the **current** verification method only (check 1) and the resolved document must be no more than `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` old (check 2), rotating `#active` invalidates every outstanding attestation signed by the retired key **within `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7 — 5 min)** — so the effect is near-immediate but not instantaneous, because a verifier still holding a fresh-enough (≤ 5-min-old) *pre-rotation* cached key state would keep resolving the retired key until that entry ages out. **That cache entry has a second effect, and it runs the other way:** the same verifier fails the rotating identity's own fresh attestation, because check 3 verifies a new-key signature against the retired key the stale entry names. The first effect delays revocation for up to the bound; the second would reject the rotating member's own Update, and the re-resolution obligation of the **Resolution failure policy** above is what stops it. This strict ≤ 5-min bound governs the cross-group **Add** path — outstanding KeyPackages fetched from relays, where the actual leaf-reuse threat lives; an already-admitted member's own leaf-changing **Updates** follow the Update posture of the **Resolution failure policy** above (rotation still revokes on any resolution *success*, and genuine compromise of an admitted member is a governance Remove). This is the revocation lever exercised in §9.12.

**Group context extensions for nesting.** Child contexts include parent context IDs and governance configuration hashes in the MLS `group_context` extensions field (§5.13.3). This cryptographically binds the parent lineage to the child's group identity — the derived `group_id` is a function of the parent references. Root contexts (no parents) have empty nesting extensions.

**Authentication Service design:** MLS delegates identity verification to an Authentication Service (AS). In SCP, the AS is fully decentralized: DID resolution provides the public key binding, and UCAN validation provides the capability binding. No centralized AS server exists. Each participant independently verifies credentials by resolving the DID and validating the UCAN chain.

**Key conditions, the content boundary, and the relying party's obligation.** The latest state-carrying event of an identity's key-event log (§9.7.4.2 definitions, R8) lists every key that has appeared on the chain as a root member or an operational key, and each listed key is in exactly one of four conditions: **`current`** — listed in a role; **`Superseded`** — listed outside every role, because a later key took the role this key held; **`Retired`** — listed outside every role, with no successor key in the role it held; or **`Compromised{from: N}`** — listed outside every role, carrying a position N in the key-event log, at or before the sequence of the event that carries the entry, from which the standing root asserts an attacker held the key. ADR-063, the inception-derived key-event-log identity substrate, fixes these four names and makes the standing root the authority that asserts them: §9.7.4.2 R3 makes every state-carrying event root-signed, so a condition survives compromise of the operational key it concerns without that key's cooperation, and it names a reason the retiring key could not name once that key is the thing being disavowed. A verifier reads the condition the entry carries and derives none of it from the roles. R8 states the obligation to list every installed key exactly once, and a verifier applies R8's text rather than a paraphrase of it.

**What each condition decides, and what it does not.** The three conditions other than `current` share one criterion: the key signs nothing new, and content the party accepted before that key's boundary in a context stays valid there. `Superseded` and `Retired` decide nothing beyond it, so no verification rule branches on which of the two an entry carries; they differ only in the reason the standing root records. `Compromised{from: N}` alone adds a test on the signer's log-anchored evidence, and the log-anchored row of the classification table below states that test once; no other sentence in this spec states it, and a verifier applies the row's text. **Where a rule anywhere in this spec calls a key *retired* in plain words, it means a key the latest state-carrying event lists in any of the three conditions other than `current`**; where a rule writes `Retired` in code font it names that one condition and no other. The controller withdraws a false alarm by a later state-carrying event that lists the key `Superseded`, `Retired`, or in a current role. An entry identifies its key by the public key bytes. **How a verifier resolves a `signing_key_id` fragment, stated once.** The fragment names a role, and the latest state-carrying event lists every key that ever held that role (§9.7.4.2 R8). For a **content-class** signature (the table below) the verifier considers every key that event lists as having held the named role, takes the key whose bytes verify the signature, and then applies that key's condition and that context's boundary to the result; a verifier that read the `current` key alone would reject every message an author signed before its last rotation. For an **attestation-class** signature the verifier reads the `current` key of the named role and no other key (check 1 above). A verifier resolves a fragment through the latest state-carrying event in both cases, and never from a list of current keys alone.

**Where the content boundary lives.** Content signed by an operational key is committed inside a context through MLS, and **the retiring identity owes an MLS Update to every context it belongs to** — a Commit, an epoch boundary every member of that context observes identically. Three rules place that obligation on it: the compromise recovery protocol (§9.12 step 2) on a compromise, the rotation rule of §9.7.3 on a planned rotation, and §9.7.4.2 R4 on the abandoning controller before it publishes. **The obligation is the identity's, and a context where the identity did not discharge it records no Commit**; the paragraph below states what a member reading such a context does. **The epoch of the Commit that follows a key's retirement is that key's boundary in that context**, whatever the reason for the retirement. The position N of a `Compromised{from: N}` entry names where in the log the standing root asserts the compromise began; the Commit epoch names where that assertion took effect in each context, and content is ordered against it by **the MLS epoch the message decrypted under, never the envelope's `epoch` field** — a compromised key's holder signs that field, so a verifier that read it would take its ordering input from the attacker (§9.8.1 inner check 1 rejects an envelope whose `epoch` field differs from the epoch that decrypted it). No further ordering structure is needed: the decryption epoch is what MLS already gives every member, and every member derives the same epoch sequence, so the boundary converges by the same mechanism that makes MLS work.

**The boundary in a broadcast context.** A broadcast context (§5.14) runs no MLS group and advances no epoch: its authors distribute per-author sender keys and stamp each chunk with the author's `key_epoch`. **In a broadcast context the boundary for a retired author key is that author's `key_epoch` at the rotation, read from the sender-key distribution the author published and never from the chunk's own field**, for the same reason the MLS rule reads the decryption epoch: the holder of the retired key signs the chunk. **A subscriber that holds a distribution recording the step orders that author's chunks against it**: it accepts a chunk whose `key_epoch` is below the step and rejects a chunk at or above it. **A subscriber that holds no such distribution reports `Invalid{no_boundary}` for that key** and re-fetches the author's sender-key distributions from the relays the author's service record names (§9.16.2). The outcome is recoverable and it fails closed: the subscriber verifies nothing under that key until a distribution reaches it, and it never accepts a chunk on the ground that it read no step.

**Abandonment sets a boundary for every key the final state lists `current`.** The abandoning controller's §9.12 step-2 Commit is the boundary in its context for every such key (§9.7.4.2 R4), so the content row below applies to an abandoned identity with no extra condition: under any key for which the context holds a boundary, the party accepts only content that reached it under an epoch before that boundary.

**"No boundary here" is a fact about the context, not a gap in the evidence.** This paragraph governs an MLS context; the broadcast arm above governs a broadcast context, and a member applies exactly one of the two. The boundary for key K in context C **exists iff C's Commit history records a retirement Commit from that identity for K**. A member reading C's Commit history, live or through a snapshot that carries that history, and finding no such Commit accepts K's content in C **on one further condition: C's Commit history records at least one Commit from that identity whose leaf attestation verified under K**. That condition is what makes the absence informative — a context that watched the identity sign under K would have watched it retire K, so the absence of a retirement Commit there says K was not retired. **A member that finds no such Commit reports `Invalid{no_boundary}` for K in C** and accepts nothing under K there: C never saw K, so C's silence about K's retirement is silence about a key C knows nothing of, and reading it as acceptance would admit content signed under a key retired before the identity ever joined C. The same condition governs an abandoned identity's keys that the final state does not list `current`. `Invalid{no_boundary}` is also the outcome when **the member holds no Commit history covering the span it must judge**, so it can neither find a retirement Commit nor establish that none exists. Both are the fail-closed direction, because a member that accepted content over a span it cannot see, or under a key its context never watched sign, would accept everything an attacker signed after a boundary it never read.

**The boundary travels with the content it bounds, and observation outranks it.** A context snapshot and a context export carry, for every identity whose key the context retired, that key's boundary epoch in that context, and the producer signs those values with the key the snapshot or export is signed under. A member that joins after the boundary Commit therefore learns the boundary from the snapshot it syncs rather than from an observation it could not have made. **Precedence:** a member's own observation of the boundary Commit outranks any snapshot value for that key in that context, so no other member rewrites a boundary the member watched happen. **Two disagreeing snapshot values fail closed.** Where a member holds two snapshot values for one key in one context and they disagree, it adopts **neither** and reports `Invalid{no_boundary}` for the span the two values disagree over, and it surfaces the disagreement to the user. The one exception is a snapshot that carries the Commit history establishing its value: the member checks the asserted boundary against that history and rejects an assertion the history does not support, so a supported assertion decides the span and an unsupported one is discarded. **A producer asserts a boundary only from Commit history it holds**, and a producer that holds no history covering the epoch it names asserts nothing for that key. Taking the earlier of two disagreeing values would hand any co-member a signed erasure of any other member's history in that context, because the earliest value bounds the most content and a producer chooses the value it signs.

**The relying party's obligation, stated over evidence it holds.** For a retired key, a relying party accepts a signature **iff** the content reached it under an epoch **before that context's boundary** for that key. One test decides it, and the test reads two inputs the party holds: the epoch the content came in under, and the boundary value. The epoch is the MLS epoch under which the party decrypted the content, with a valid `membership_tag` (§9.8.1 check 2), for content the party received live; for content inside a snapshot or an export it is the epoch the producing context recorded for that item, attested by the producer on the snapshot. The boundary value is the one the party observed at the boundary Commit, or the one the snapshot or export carried to it under the precedence above.

**Which context's boundary a cross-context artifact is compared against.** "That context's boundary" is the boundary of the context **through which the relying party accepted the content**. A cross-context receipt that Bob accepted in context B is therefore compared against B's boundary for the signer, under the evidence B gave Bob, and Bob needs no membership in the producing context to verify it. A party verifies content only through a context it belongs to, on the evidence that context gave it, and holds no evidence about a context it never joined.

A key the state does not list `current` is not a live signing capability, and the position N of a `Compromised{from: N}` entry never unmakes what the party already accepted before the boundary. The controller's key event is never rejected on account of content.

**Every signed structure is classified.** The table below states, for every registered separator that an operational key or root signs, which condition its signature verifies under. The default for a separator this table does not list is the attestation class.

| Class | Rule | Separators |
|---|---|---|
| **Attestation** — current key only | verifies against the identity's current key for that role (check 1 above); a retired key's signature never verifies | `SCP-KEYPACKAGE-ATTESTATION-V1:`, `SCP-ATTESTATION-V1:`, `SCP-PARTICIPATION-V1:`, `SCP-PARTICIPATION-PROFILE-V1:`, `SCP-KEY-REQUEST-V1:`, `SCP-ACCESS-KEY-REQUEST-V1:`, `SCP-EPOCH-ADVANCE-V1:`, `SCP-BLOCK-NOTIFICATION-V1:`, `SCP-CHALLENGE-REQ-V1:`, `SCP-CHALLENGE-RESP-V1:`, `SCP-CHALLENGE-VERIFY-V1:`, `SCP-BRIDGE-REGISTER-V1:`, `SCP-PUSH-REGISTER-V1:`, `SCP-PUSH-DEREGISTER-V1:`, `SCP-INVITATION-BUNDLE-V1:`, `SCP-JOIN-RESPONSE-V1:`, `SCP-SERVICE-RECORD-V1:` (the role is the service-key designation, `03-identity.md` §3.10.13), UCAN tokens, and every separator this table does not list |
| **Content** — accepted before the boundary | the relying-party obligation above: verifies under a current key, and under a retired key only for content that reached the party under an epoch before that context's boundary for that key | `SCP-INNER-ENVELOPE-V1:`, `SCP-BROADCAST-ENVELOPE-V1:`, `SCP-VOTE-V1:`, `SCP-PROPOSAL-V1:`, `SCP-RECEIPT-V1:`, `SCP-XCTX-RECEIPT-V1:`, `SCP-XCTX-STREAM-RECEIPT-V1:`, `SCP-XCTX-DIVERGENCE-V1:`, `SCP-OUTLET-CHUNK-SIG-V1:`, `SCP-OUTLET-CREDIT-V1:`, `SCP-OUTLET-CANCEL-V1:`, `SCP-RESET-REQUEST-V1:`, `SCP-COMMIT-RANGE-REQ-V1:`, `SCP-COMMIT-RANGE-RESP-V1:`, `SCP-CHECKPOINT-V1:` |
| **Log-anchored evidence** — anchored to a key-state position | the artifact carries `key_state_head` inside the signed preimage (§9.5.2). **`key_state_head` is the §9.5.1 preimage digest of the latest state-carrying event at or before the moment the signer signed** — the digest R13 takes over that event's signed preimage, naming the position at which this row's `current` test is read. This sentence is the one construction of the field, and §9.5.2 and §9.15 cite it. The signature verifies **iff** the signing key was `current` at that position, and, where the entry is `Compromised{from: N}`, only under the further test the paragraph below states. A key the state lists `Superseded` or `Retired` keeps its signature valid for this class, because the artifact names when it was made | `SCP-KEY-DESTRUCTION-V1:`, `SCP-CONTEXT-SNAPSHOT-V2:`, `SCP-CONTEXT-EXPORT-V2:` |
| **Key event** — the log's own rules | §9.7.4.2 R3 | `SCP-KEL-EVENT-V1:` |

**Why the log-anchored class exists, and the limit it carries.** An artifact a party publishes as evidence against a future version of itself cannot verify under the attestation class, because the signer would void it by any routine rotation of the key it controls. §9.15's destruction attestation is such an artifact: it is published to relays, outside any context, so no context epoch orders it and the content class has no test to apply. A durable context snapshot and a durable context export are such artifacts too, and for a second reason: a snapshot signed under a key the producer later rotates is the very record that teaches a later joiner where that key's boundary lies, and the content class would reject it at every member who received it after the boundary. Anchoring these three artifacts to a key-state position gives them an ordering the signer cannot revise after the fact, because the key-state head digest is fixed by the log. **The limit, stated because it is not a guarantee against the compromised key's holder:** the signer chooses `key_state_head`, so a party holding a key the state lists `Compromised{from: N}` can anchor a forged artifact before N. A verifier therefore accepts such an artifact **only** when it held that artifact before it adopted the event that carried N — first-seen, recorded with the adoption — **or** when a party independent of the signer countersigned it. Against a compromised key with neither condition met, this class gives no guarantee, and a verifier rejects. `SCP-CHECKPOINT-V1:` (§9.9.3) needs no anchor at all: a member accepts a consistency checkpoint through MLS inside the context, so the content class already orders it. **Which artifacts are durable:** a context snapshot and a context export are durable artifacts, stored and re-served after the epoch that produced them, which is why they carry per-item epochs and their own key-state anchor; every separator in the content row is live traffic a context ordered when it arrived.

Governance votes and proposals are content: a vote cast under a key that is later marked compromised stays counted for the members who accepted it before the boundary, because the alternative — every vote in a context's history rejected the moment a key is asserted compromised — would let a compromise assertion rewrite governance outcomes. The key-event record frame carries no signature of its own (§9.10.12), so this table classifies none: a relay authorizes a write by verifying the chain the frame carries, and a resolver authenticates the record by that same chain (§9.6.1). A key-continuity fingerprint (§9.11) is a hash, not a signature, and is outside this table. Rationale for the default: a structure nobody classified is safer read as current-only than as content, because the content class admits historical keys.

**Every verdict the resolution policy must consume.** The resolution-failure policy of check 2 has, for each trigger, a branch for resolution failure and a branch for a resolution that returns a rotated key. The six verdicts of §9.7.4.2 R14 partition across those branches as follows, and the policy MUST route each one.

- `Confirmed` and `Adopted` are the **success** branch, and both refresh the accepted key state.
- `Discarded{accepted_head}` is **not** the success branch: the verifier discarded a candidate at a strictly lower sequence on the accepted chain and stays on the baseline it already held (§9.7.4.2 R12), so the resolution refreshed nothing and check 2's freshness bound decides what happens next — where the held baseline is older than `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`, the resolution has not succeeded and the failure branch applies. Routing a discarded stale candidate to the success branch would let a party that suppresses the newer head and serves an older genuine one pin every verifier on a baseline listing a stolen key `current`, at no cost and repeatably.
- `Inconclusive` is the **failure** branch: an Add rejects, and an already-admitted member's Update falls to the bounded last-known-good grace. A verifier reports the resolution failure by the cause the verdict names and never as a generic outcome.
- `Invalid{at_event}` **rejects on both triggers and never reaches the grace.** A chain the verifier has judged invalid is not a transient resolution failure, so an Add rejects, an already-admitted member's Update rejects, and the verifier MUST NOT fall back to a last-known-good key state for it. Routing it to the failure branch would hand the pin-to-stale attack to any party that can serve one invalid chain.
- `Contested` is its own branch. §9.11's gate list is authoritative for the acts a verifier withholds from a contested identifier, and this paragraph adds no act to it. Three things are decided here rather than there. **A leaf-replacing Update is held, never admitted:** on a `Contested` verdict a verifier admits no Update that replaces the identifier's MLS leaf. It holds the Update and surfaces it to the human, exactly as §9.11 directs for an Add-carrying Commit from a `PendingReverify` member, and it checks the Update against no key state at all. The reason no key state serves: the party that authored the divergence chose where the two chains part, so it chose the shared prefix, and a verifier that read the shared prefix's key state would take its verification basis from the attacker — the same capability R6's rationale names when it refuses to rank chains by their first divergent event. A leaf replacement is the one act that hands a membership to whichever claimant sends it first, so holding it costs an honest controller a human step during a state that is already terminal by key material (R7). **Leaf eviction:** the verdict alone evicts no leaf, and §9.12 step 1a proposes Remove for no leaf on a `Contested` verdict. **Content verification** for that identity uses the shared prefix's key state as its basis for content the member accepted under an epoch no later than the last Commit that context observed from the identity before the member first observed any divergent suffix (§9.7.4.2 R7), and verifies nothing after that anchor; the anchor reads what the member observed, never where the divergence's author placed the fork. **A contested identity acquires no new boundary from the contest**, because it retired no key in the contest and issued no §9.12 step-2 Update for it. Every boundary the shared prefix already set still binds: a key the shared prefix retired stays retired for content the member places before the anchor, and the member applies that key's boundary in the ordinary way. A member that cannot place content before the anchor reports `Invalid{no_prefork_basis}`.

A `RootRecovery` that is `Adopted`, and a `Contested` verdict, both set the identifier's `ContinuityStanding` to `PendingReverify` under §9.11, and every gate reads that one standing.

**A content-signature freshness bound, and what a failed refresh does.** Content signed by a newly installed operational key can reach a verifier before the verifier has the `KeyState` that installed it, and §9.8.1 rejects an unresolvable signature rather than holding it, so the content is lost. A verifier MUST therefore refresh the signer's key-event log before rejecting a content signature whose `signing_key_id` it cannot resolve, and MUST treat a key-event log older than `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7) as stale for that purpose — the same bound check 2 places on attestation resolution. **The refresh has two outcomes and each has a direction.** On a resolution **success** that still cannot resolve the `signing_key_id`, the verifier rejects the content immediately: the log is current and does not name that key. On a resolution **failure** the verifier holds the content for `CONTENT_RESOLUTION_RETRY_WINDOW` (§9.18.17), retrying within the window, and rejects when the window closes; it holds at most `MAX_PENDING_CONTENT_PER_SENDER` (§9.18.17) items per sender and drops the oldest beyond that, so a party sending content under fabricated `signing_key_id`s while it degrades the verifier's resolution fills a bounded buffer and nothing more.

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

MLS provides PCS through the Update proposal mechanism. After a member sends an Update (generating a fresh HPKE key pair and ratcheting their path in the tree), any previous compromise of that member's state becomes useless for future messages **in that group**.

**Scope of the PCS bound (in-group only).** PCS bounds the compromise of a leaf's MLS state *within the group where the Update happens* — it does not, on its own, bound reuse of a leaked leaf key plus its **standalone KeyPackage attestation** to join **other** groups. An attacker holding a victim's leaf `signature_key`/`encryption_key` and the attestation over them can present that leaf to a different group until either the attestation's capped lifetime expires (`MAX_KEYPACKAGE_ATTESTATION_LIFETIME`, §9.18.7) or the victim rotates `#active` (§9.12), whichever comes first — because verifiers resolve the signer's **current** verification method only (§9.7.1 check 1). It is therefore **incorrect** to say such a compromise is bounded by the PCS Update interval; that interval bounds only the in-group message-read window (§9.12 "Time-shifted key compromise"). Rotation is the immediate revocation lever for the cross-group reuse vector; the lifetime cap is the backstop.

**SDK requirements:**

- The SDK MUST periodically issue MLS Update proposals. Recommended interval: every 24 hours for active contexts, or immediately after any suspected compromise. Because an Update generates a fresh ephemeral leaf key and ratchets the path, the updated leaf MUST carry a fresh **KeyPackage attestation** binding the new leaf `signature_key` to the DID (§9.7.1).
- The SDK SHOULD issue an Update after re-establishing connectivity following an offline period.
- When an Active Signing Key rotates by a `KeyState` event (§9.7.4.2 R3), the SDK MUST issue an MLS Update in every active context with a new credential AND a **KeyPackage attestation re-issued under the new `#active` key** (a fresh `#active` signature over the leaf's ephemeral MLS key). This synchronizes key rotation with MLS-level post-compromise security. The MLS leaf `signature_key` is ephemeral and never equals the rotated DID key — only the attestation over it is re-signed.
- When a delegated agent identity rotates its own Active Signing Key, that identity runs the bullet above on its own key-event log, because it holds its own keys and the human's log holds none of them (§9.1 invariant 1).
- When the root key changes by a `RootRecovery` (§9.7.4.2 R3), the identifier does not change and no `DidRotationEvent` exists; the SDK MUST issue MLS Updates in every active context with the new credential and a **re-issued KeyPackage attestation** under the operational keys the recovery's key state names. §9.11's key-change rule governs what every peer does on observing it.

**PCS Update interval as context parameter:** High-security contexts may configure shorter PCS Update intervals (e.g., 1 hour). The interval is a context-level parameter set at creation, defaulting to 24 hours.

### 9.7.4 Key Lifecycle

**Key generation:**

- Root set (Ed25519, one or more members with a signing threshold; §9.7.4.2 definitions): each member is generated in a substrate that signs raw Ed25519 and never exports the private key — a hardware token with an OpenPGP-card applet, an Ed25519-capable HSM, or a software keystore (§9.7.4.1 item 4 names the substrates; Apple's Secure Enclave and Android StrongBox hold P-256 only and cannot hold a root member). Used ONLY for establishment events (§9.7.4.2 definitions). It fixes a pre-rotation commitment only inside the inception event; after inception, only a reveal-authorized event fixes a new commitment, and the root alone never re-commits (§9.7.4.2 R1). The identifier is the inception event's digest (§9.7.4.2 R2), not a derivation of any key, and it never changes.
- Active Signing Key (Ed25519): Generated via KeyCustody. Used for MLS KeyPackage attestations (§9.7.1), inner-envelope signatures, UCAN issuance. It does NOT sign the MLS leaf/credential directly — the leaf is self-signed by the ephemeral MLS leaf signature key (below), and the DID↔leaf binding is carried by a `#active`-signed KeyPackage attestation. Rotated by a `KeyState` event signed by the standing root (§9.7.4.2 R3). The identifier does not change on active key rotation.
- Next set (Ed25519, one or more pre-rotation keys with a next threshold): generated at identity creation and again as the successor set at every reveal (§9.7.4.1 items 1, 6), held in custody independent of the operational path (§9.7.4.1 item 3a). Each member is a one-shot authorizer: it signs exactly one reveal-authorized event (§9.7.4.2 definitions) and is then spent and destroyed (§9.7.4.2 R5); it never becomes a root member or any other key.
- MLS leaf HPKE keys (X25519) — these are **three distinct** keys, NOT one; RFC 9420 keeps them separate and so does SCP:
  - LeafNode `encryption_key`: the **ratchet-tree** HPKE key (RFC 9420 §7.2) to which path secrets are sealed on Commits. Lives on the leaf in the ratchet tree. Generated by the MLS library per the selected ciphersuite, stored in platform secure storage, re-generated on every Update/PCS rotation.
  - KeyPackage `init_key`: the HPKE key the Welcome's `EncryptedGroupSecrets` is sealed to at join (RFC 9420 §7.1). **`init_key != encryption_key`** — it lives ONLY in the published KeyPackage, is single-use, and is **consumed at join** (never enters the ratchet tree). It is the read-at-join vector, which is why the KeyPackage attestation binds it and the verifier checks it at Add/Welcome time only (§9.7.1, §9.5.2).
  - `scp_wrapping_key` (`0xFF01`): the stable X25519 HPKE key used to wrap §9.16 per-sender key distributions (§9.16.2). Published as a LeafNode extension; distinct from both keys above and does not rotate on epoch advance.
  All three are bound to the DID by the KeyPackage attestation (§9.7.1, §9.5.2) and are distinct from the leaf signature key below.
- MLS leaf signature key (Ed25519): The leaf's `signature_key` — an **ephemeral, context-scoped** key generated by the MLS layer (`SignatureKeyPair::new()`), one per group, re-generated on every Update/PCS rotation (§9.7.3). It self-signs the LeafNode and is DISTINCT from every root member and from the Active Signing Key (`#active`) — it is never a DID verification method and MUST NOT be expected to resolve to one. It is bound to the member's DID out-of-band by the `#active`-signed KeyPackage attestation (§9.7.1, §9.5.2), which is re-issued whenever this key is re-generated. Never persisted beyond the MLS group state; destroyed with the leaf on Update or group exit.
- KeyPackages: Pre-generated and published to relays. Each KeyPackage is single-use. The SDK MUST maintain a buffer of at least 10 unused KeyPackages per identity on relays. Replenished when the buffer drops below 5.
- UCAN signing key: Active Signing Key (Ed25519) for root UCANs. UCAN tokens are signed by the human's Active Signing Key — never by a root member. On active key rotation, existing UCAN tokens are revoked and reissued under the new Active Signing Key. Agent-autonomous actions use scoped UCANs that the human's Active Signing Key issues to a delegated agent identity as the token's audience. That agent invokes such a token under its own `#active`, and no agent signs the human's root UCAN.

**Key distribution:**

- Root set and operational keys: carried in the identity's key-event log; a resolver derives them from the latest state-carrying event (§9.7.4.2 R8).
- KeyPackages: Published to relays via the transport adapter. Any party wanting to add this identity to a group fetches a KeyPackage from their relay.
- Context group key: Distributed via MLS Welcome message, encrypted to the new member's KeyPackage. Only the intended recipient can decrypt.

**Key rotation:**

- Active Signing Key: Rotated by a `KeyState` event signed by the standing root (§9.7.4.2 R3) that lists the new `#active` `current` and the old one `Superseded` (§9.7.1). All active MLS groups receive an Update proposal with the new credential. The identifier does not change. §9.11 states which observers set `PendingReverify` on that event and which do not.
- Root set: Changes only by a `RootRecovery` (§9.7.4.2 R3), which installs a fresh root set and carries the complete post-recovery key state (§9.7.4.2 R8) — a rare operation. The identifier does not change (§9.7.4.2 R2). No migration proof exists: the recovery event is signed under `"SCP-KEL-EVENT-V1:"` like every other key event (§9.7.4.2 R13). §9.11's key-change rule governs what every peer does on observing it.
- MLS epoch keys: Rotated automatically on every Commit (membership change or Update).
- UCAN tokens: Expire per their `exp` field. Re-issued by the human's Active Signing Key. On active key rotation, all UCAN tokens signed by the old Active Signing Key are revoked and reissued under the new key. A delegated agent identity's own key rotation revokes no token the human issued, because a scoped UCAN names that agent's identifier as its audience and the identifier does not change when the agent rotates a key (§9.7.4.2 R2). Revocations are added to the per-context `RevocationList` and distributed as MLS application messages (see §9.5 UCAN revocation, ADR-016 criterion 5).

**Key destruction:**

- Ephemeral context close: Destroy MLS group state — tree secrets, all epoch key schedules, application key material. See §9.15 for destruction verification.
- KeyPackage consumption: After a KeyPackage is used in a Welcome message, the SDK deletes the KeyPackage's private key. One-time use is mandatory.
- Old epoch material: Destroyed after Commit processing (forward secrecy, §9.7.2).

### 9.7.4.1 Pre-Rotation Key Custody

The pre-rotation key is the identity's recovery path after root compromise and, at the same time, the key whose leak is least recoverable (item 4 below); it is a backstop only while its custody holds. §9.7.4.2 states the events that consume it and the rule that ranks competing chains; §9.12 states the ordered recovery protocol around those events. Its custody MUST be specified with the same rigor as a root member's.

**Custody requirements:**

1. **Generation.** The pre-rotation keypair MUST be generated on the device during identity creation, using the platform's CSPRNG. The private key MUST NOT be generated on a remote server.

2. **Commitment publication.** The pre-rotation commitment (§9.7.4.2 definitions) is a field of the inception event and of every reveal-authorized event; the controller publishes it as part of that event. Only the commitment is published. The public key appears only inside the reveal-authorized event that consumes the commitment.

3. **Storage isolation.** The pre-rotation private key MUST be stored separately from every root member and from the Active Signing Key. It MUST NOT be accessible through the same custody provider or authentication flow used for daily operations. This ensures that compromise of the operational custody path does not compromise the recovery path.

3a. **Recovery-authority residence (normative).** Item 3's storage-isolation requirement constrains *where the recovery authority resides*, not merely which provider object holds the key handle. The **recovery authority** is the minimal secret, key handle, or authorization capability sufficient to recover the pre-rotation private key. It MUST reside in a substrate whose compromise is **independent** of operational-custody compromise: there MUST NOT exist any secret, key handle, or authorization capability reachable **(directly or transitively, following any key-wrapping or key-derivation chain to its root)** from the operational `KeyCustody` provider or the daily-operations authentication flow that — alone or in combination with publicly-stored artifacts (including the encrypted-offline ciphertext of item 4) — suffices to recover the pre-rotation private key. Wrapping the key in an approved cipher (item 4) does NOT by itself satisfy this requirement: the §3 adversary is one who has already compromised operational custody, and if the decryption authority for that cipher is itself reachable from operational custody, the cipher provides zero protection against that adversary. The load-bearing property is **principal-distinctness of the recovery authority**, not the strength of the cipher wrapped around the key.

   **Fail closed — no fallback (normative).** If no substrate satisfying this recovery-authority-residence requirement is available, identity creation MUST fail closed with a typed error. There is no fallback to co-located operational storage, and no fallback to an in-memory or other dev/test stand-in for the recovery authority. A recovery authority reachable from operational custody is a violation, never a degraded default.

   **A reveal is not a daily operation.** A reveal-authorized event (§9.7.4.2) is a rare, separately-authorized event, not a daily operation. A distinct reveal-time authorization principal — even one that is fully automated (e.g., a separate KMS role assumed only for a rollover or recovery, which the operational path holds no grant to assume) — satisfies this requirement. What does NOT satisfy it is the daily operational signing flow itself being able to reach the pre-rotation key.

   This is an **at-rest / daily-operations** property. It constrains where the recovery authority lives when no reveal-authorized event is in progress. During an authorized rollover or recovery the pre-rotation key signs the event where it resides and is never imported into operational custody; a `RootRecovery` installs a fresh root generated in operational custody, not the revealed key (§9.7.4.2 R3 and R10).

   The fail-closed-no-fallback rule above and the recovery-authority-residence property are canonical and normative here. Items 4 (approved custody methods) and 5 (SDK presentation) below are canonical, and item 4's conformance table states which method conforms on which profile.

4. **Approved custody methods.** Under the key-event log a copy of a pre-rotation key alone does more lasting damage than a copy of the root alone: a root leak is recoverable by a reveal, while a leaked pre-rotation key lets its holder contest the identity at any later date and, held exclusively, take it over and then kill it permanently (the failure-mode table below). The pre-rotation key is therefore the backstop against root compromise and at the same time the key whose leak is least recoverable, and its custody is ranked on two axes with **post-spend destructibility** as the primary one: whether the controller can destroy every copy of a spent key (§9.7.4.2 R5) and, where the substrate supports it, obtain the §9.15 attested destruction; and resistance to theft at rest. Any one method is sufficient **subject to the recovery-authority-residence requirement of item 3a**. Every method MUST hold an Ed25519 key that signs the raw §9.5.1 preimage of a key event (§9.7.4.2 R3). A WebAuthn/FIDO2 authenticator signs only `authenticatorData || SHA-256(clientDataJSON)` under its own counter, and Apple's Secure Enclave and Android StrongBox hold P-256 keys only, so none of those substrates can produce the signature R3 requires, and this table names none of them.

   | Method | Theft resistance | Post-spend destructibility | Description |
   |--------|------------------|----------------------------|-------------|
   | Hardware token with an OpenPGP-card applet (Ed25519) | Highest | Destroyable by on-token key deletion; attested only where the token attests deletion | Key generated on and resident in a dedicated hardware token whose OpenPGP applet signs raw Ed25519 messages (for example a YubiKey 5). The key never leaves the hardware; signing requires physical possession. |
   | HSM-resident key (Ed25519-capable HSM) | Highest | Destroyable with §9.15 attested destruction | Key generated in and resident in an HSM under a principal the operational path holds no grant to assume (item 3a). |
   | Secondary-device software keystore (Ed25519) | High | Destroyable by software zeroize (§9.15 software-only confidence) | Key held in the software-backed keystore of a device NOT used for daily SCP operations (for example a tablet kept at home while the phone is the daily driver). |
   | Platform-backed cloud key store | Medium | **Not destructible** — the platform retains historical snapshots the controller cannot verifiably purge | Key stored in platform key backup (iCloud Keychain with Advanced Data Protection, Google Cloud Key Vault). Recoverable through platform account recovery. |
   | Encrypted offline backup | Medium | Destructible only when every physical copy is destroyed | Private key encrypted with AES-256-GCM using a key derived from a user-chosen passphrase via Argon2id (memory: 64 MiB, iterations: 3, parallelism: 4). Stored offline (USB drive, printed QR code, or secure note). The SDK MUST generate the passphrase with at least 128 bits of entropy if auto-generated. |
   | Shamir secret sharing (3-of-5) | Medium | **Not destructible** — shares held by contacts are outside the controller's control | Private key split into 5 shares using Shamir's Secret Sharing (GF(2^8)), any 3 sufficient to reconstruct. Each share is 33 bytes (1 byte index + 32 bytes data). |
   | Paper backup (BIP39 mnemonic) | Lowest acceptable | **Not verifiably destructible** — a copy is one photograph away | Private key encoded as a 24-word BIP39 mnemonic, stored physically. The SDK MUST warn that loss of the paper backup eliminates the recovery path. |

   **A non-destructible sole custody has a terminal failure mode, and no layer mitigates it today.** When the controller cannot destroy every copy of a spent pre-rotation key, any copy that later reaches any party lets that party fork before the event that spent the key and reveal the same commitment; both suffixes are then rank 1, and R7 makes the identity contested and terminal by key material at any later date. The witness layer is the only other mitigation, and §9.7.4.3 does not yet carry its protocol, so until that section lands no layer mitigates this failure. The SDK MUST state that outcome at custody selection, in those terms, whenever the user selects a method the table marks not destructible or destructible only by destroying every physical copy. This section discloses the choice and does not forbid it: a controller MAY select a non-destructible method as its sole custody, having read the disclosure.

   **Method × profile conformance.** A method conforms on a profile when that profile can hold the method's substrate and reach it at reveal time under item 3a. "Conforms" means the SDK MAY offer the method on that profile; "does not conform" means the SDK MUST NOT offer it there.

   **A reveal may be human-attended on every profile, the server profile included.** Item 3a already states that a reveal-authorized event is a rare, separately authorized event and not a daily operation, so no profile's cell turns on whether a human is present when the reveal runs. Three of the methods below need a human act at reveal time on every profile — re-entering a mnemonic, supplying an Argon2id passphrase and mounting the offline medium, and collecting three Shamir shares from their holders — and the table answers all three the same way. What a cell does turn on is whether the profile can hold the substrate and reach it under item 3a's principal-distinctness test.

   | Method | Server | Desktop | Mobile | Browser |
   |---|---|---|---|---|
   | Hardware token with an OpenPGP-card applet (Ed25519) | Conforms — USB or smartcard reader attached to the host | Conforms — USB or NFC | Conforms — NFC or USB-C token | Does not conform — no browser API reaches an OpenPGP-card applet for raw Ed25519 signing |
   | HSM-resident key (Ed25519-capable HSM) | Conforms — the primary server method | Conforms — network HSM under a separate principal | Conforms — network HSM under a separate principal, reached over the network the same way | Does not conform — a browser holds no credential for a principal the page's own origin cannot reach |
   | Secondary-device software keystore (Ed25519) | Does not conform — a server has no second device in the controller's hands | Conforms — a second device the controller owns | Conforms — a second device the controller owns | Does not conform — the browser is not the second device's custody surface |
   | Platform-backed cloud key store | Does not conform — a server profile has no platform account distinct from its operational credentials | Conforms | Conforms | Conforms |
   | Encrypted offline backup | Conforms | Conforms | Conforms | Conforms |
   | Shamir secret sharing (3-of-5) | Conforms | Conforms | Conforms | Conforms |
   | Paper backup (BIP39 mnemonic) | Conforms | Conforms | Conforms | Conforms |

   Every conforming cell is still subject to item 3a: the SDK MUST reject a selection whose recovery authority is reachable from the profile's operational custody, whatever this table says. That test, not the table, is what rejects a mobile HSM arrangement whose KMS grant the mobile application's operational signing flow can assume.

5. **SDK presentation.** At identity creation, and again for the successor key before every reveal-authorized event (§9.7.4.2 R10), the SDK MUST:
   a. Generate the pre-rotation keypair (item 1).
   b. Present the user with custody options (item 4, both axes shown).
   c. Guide the user through the selected custody method.
   d. Verify the backup (for offline methods: require the user to re-enter or re-scan the backup before proceeding).
   e. Sign and publish the event that carries the commitment — the inception event at creation (§9.7.4.2 R2), or the reveal-authorized event that fixes the successor commitment (§9.7.4.2 R4) — only after backup verification succeeds.
   f. Destroy the pre-rotation private key from the creating device's memory after backup is confirmed.

6. **The successor key at every reveal.** Every reveal-authorized event fixes the next pre-rotation commitment inside the same event (§9.7.4.2 R4). The successor key follows items 1, 3a, 4, and 5b–5d before the event is signed; §9.7.4.2 R10 states when in the ceremony, and §9.7.4.2 R5 states the destruction of the spent key.

7. **Custody status tracking.** The SDK SHOULD periodically prompt the user to verify their pre-rotation key backup is still accessible (e.g., every 6 months). This is a client-level reminder, not a protocol-level enforcement — the protocol cannot verify that an offline backup still exists.

8. **Standing-key retention.** The controller MUST retain every standing pre-rotation private key — each key's backup under item 4 — from the moment the commitment list is fixed until a reveal-authorized event supersedes that list, on every code path. The obligation covers every member of the set and ends for the whole set at that event, whether the reveal named the member or not; §9.7.4.2 R5 then destroys the whole set. Loss of the standing key forecloses both reveal-authorized event kinds, because the standing root alone cannot fix a new commitment (§9.7.4.2 R1); the failure-mode table below states the outcome. Item 7's periodic verification is the client-level check on this obligation.

**Failure modes.** Each row names the keys the attacker holds and the outcome the rules of §9.7.4.2 produce over key material alone. Two parties who each hold enough of the next set to reveal can each reveal, and key material cannot tell their events apart: those rows are contested (§9.7.4.2 R7), and a party applying a witness policy over a recognized-independent set resolves them for itself (§9.7.4.2 R6); until the witness protocol is specified, a contested identity stays contested. Where a row says the root cannot be recovered by key material and no witness policy applies, the person establishes a new identity and each context's admins remove the old identity and admit the new one — after confirming the head from a relay in the fallback set (§9.7.4.2 definitions), which the hostile identity's service record does not name (§9.7.4.2 R4). The social recovery of `03-identity.md` §3.3 does not apply to those rows, because §3.3 re-establishes custody of the same identity. Rank numbers refer to §9.7.4.2 R6. "P" below means enough of the next set to reveal; for a personal identity that is one key.

- **Pre-rotation backup lost, root intact.** The identity keeps operating. The controller can sign no `CommitmentRollover` and no `RootRecovery`, because both require a reveal, and the root alone cannot fix a new commitment (§9.7.4.2 R1); it also cannot abandon, because abandonment is a reveal-authorized event. The SDK MUST warn that root recovery and retirement are no longer possible. Item 8 is the obligation whose breach produces this state.
- **Pre-rotation backup lost, root compromised.** Both suffixes are rank 2 and the tie is pending, and no party can end it. The root cannot be recovered by key material.
- **P copied, root intact and trusted.** Both parties can reveal, so both suffixes are rank 1 and the identity is `Contested`, terminal by key material (§9.7.4.2 R7). An intact root does not contain the outcome: the controller's `CommitmentRollover` carries the root's co-signature as evidence a party's witness policy weighs (§9.7.4.2 R6, Pin A), and until the witness protocol is specified in this corpus no party has a policy to apply, so every party holds the contested verdict and §9.11 sets the identifier `PendingReverify` at each of them. The rollover fixes a commitment the attacker cannot reveal, which stops the attempt from being repeated on the controller's suffix; it does not win the contest already standing.
- **P copied, root lost.** Both parties sign a `RootRecovery{Lost}`: contested, with no co-signature on either side.
- **P exclusively the attacker's, whatever the state of the root.** The attacker reveals and the controller cannot: the attacker's suffix is rank 1 against rank 2 and the attacker's `RootRecovery{Lost}` is adopted uncontested. From that point the attacker is the standing root and holds every power of the controller — including abandonment under the commitment its own recovery fixed — so **the attacker kills the identity permanently**, and the identity is dead. Item 3a exists to keep this case from arising through operational-custody compromise; no key-material mitigation exists once the key is exclusively the attacker's, and this row is why the custody table ranks destructibility first.
- **A copy of P forks before the controller's abandoning rollover.** The controller holds its root and publishes an abandoning `CommitmentRollover`; a holder of a copy of P forks before it with a `RootRecovery{Lost}` revealing the same commitment. Both suffixes are rank 1: the abandonment is never adopted, the controller may not extend past its own abandonment (§9.7.4.2 R4), and relying parties may not act on an unconfirmed head — the retirement never takes effect. Order helps and does not resolve: a controller that suspects a copy signs a `RootRecovery{CoSigns}` on its own suffix first, retiring the contested root set and consuming the commitment the copy could reveal, and then abandons under K′ (§9.7.4.2 R10). **That order forecloses the copy holder's extension past the commitment K′ fixes, and it ends no contest**: the copy holder forks behind the `RootRecovery{CoSigns}`, between the last event both chains share and the recovery, reveals the same commitment there, and stands at rank 1 beside the controller. This row stays contested after the two-phase retirement, and no ordering of key material changes that.
- **Root compromised, P held only by the controller.** The controller signs a `RootRecovery` — `CoSigns` while it still holds the root, `Lost` otherwise. Its suffix is rank 1 against the attacker's rank 2, so it wins wherever the attacker forked; the recovery's snapshot (§9.7.4.2 R8) replaces every install the attacker made, and its K′-signed chain has its own store slot, keyed to K′ (R9), so the attacker cannot evict it.
- **Root compromised and P copied.** Both parties can reveal: contested (Pin A governs the co-signature).
- **Root compromised, owner recovered, and a backup of a spent pre-rotation key later reaches an attacker — whether or not the attacker also holds the superseded root.** The attacker forks before the event that spent the key and reveals it again: both suffixes reveal the shared prefix's standing commitment, so the identity is contested at any later date. Destruction that reaches every backup medium (item 4's destructibility axis, §9.7.4.2 R5) is what prevents the contest from arising. §9.7.4.2 R5 destruction and item 5f destroy, and item 5d verifies, only the controller's own copies.
- **Two devices both holding the root, no attacker.** Neither suffix reveals, so both are rank 2 and the tie is pending. The controller ends the tie by signing a `CommitmentRollover` or a `RootRecovery{CoSigns}` on the suffix it keeps (§9.7.4.2 R10).

**Partial-publish recovery.** A reveal-authorized event has one irreversible step, the reveal; §9.7.4.2 R10 states the ceremony order, the retention invariant that makes destruction safe, the definition of confirmed publication, and the typed recovery handle that is persisted before publication.

### 9.7.4.2 Root-Authority Recovery and Fork Precedence

This section states how an identity's root recovers from compromise and how a verifier decides between two key-event chains that diverge from a shared prefix. §9.7.4.1 supplies the recovery key's custody rules; this section states the events that consume that key and the rule that ranks competing chains. Every statement below is a verifier obligation or a controller obligation. The identity spec and the identity ADRs cite this section and do not restate its rules. The rules of this section read **key material only**; the witness layer (definitions below) supplies a second, independent axis of evidence, and R6 names the slot where a party's witness policy reads it.

This section governs a **non-delegated** identifier. For a delegated identifier the delegator's chain anchors the delegate's establishment events by a key-event seal (definitions), so precedence for a delegated chain reads the delegator's chain; ADR-064, the forthcoming specification of the cooperative-delegation events, states the delegation model. Until it lands a verifier rejects a chain that claims delegation, **and R3's bullet on a nonzero `delegator` is the rule that rejects it** (`Invalid{at_event}`, whose only cause R14 names is an R3 bullet). **A chain claims delegation when its key state carries a nonzero `delegator`**; the all-zero placeholder is a non-delegated identity (definitions), and no other field expresses the claim.

**Definitions.**

- The **root** of an identity is a **root set** — an ordered list of at most `MAX_ROOT_SET_SIZE` public keys (§9.18.17) — with a **signing threshold** t. A **root signature** is an **indexed signature group**: the signed preimage names the list of root-set indices that sign, the signature field carries exactly one 64-byte slot per named index in index order, every indexed signature MUST verify against the member at its index, and the named indices MUST number at least t and MUST be distinct. Every statement below that says a root "signs" means a root signature. A personal identity is the 1-of-1 case: one key, threshold one, one index, one slot. An organization sets a list and a threshold so that no one officer acts alone. The **standing root** at a position in a chain is the root set and threshold the latest root-installing event at or before that position installed: the inception event installs the first, and a `RootRecovery` installs each later one.
- An **operational key** is a signing key other than a root member — currently the Active Signing Key `#active`, which is the identity's one operational role.
- Every key event is an **establishment event**: each of the four kinds (R3) installs, restates, or commits the identity's key material. The root signs establishment events and nothing else; operational keys sign content and attestations and never sign an establishment event. That separation is what lets a compromised operational key be retired without the root's cooperation being in question, and what keeps the root cold.
- An event's **sequence** is its predecessor's sequence plus one, and the inception event's sequence is zero; a verifier rejects an event whose sequence is anything else (R3). A **position** in a chain is that sequence, so chain order and position order are one order, and every rule below that says "position" means the sequence.
- The **community relay list** is a single artifact the SDK ships: a fixed list of relays, each entry declaring the **operator identity** that runs it, published with the SDK and identical in every binding of one release. `18-addressability-and-deployment.md` §18.5.1 defines the artifact and its entry shape; this definition and that section are the only two homes, and no rule draws the list from a bootstrap priority order. The **fallback set** for an identity is the set of entries of the community relay list the identity's own service record (`03-identity.md` §3.10.13) does not name. This definition is the one home of the fallback set, and every rule below cites it. **The set can be empty**, because an identity whose service record names every bootstrap relay leaves none outside it; the consequence is fail-closed and stated where each rule reads the set — R11 returns `Inconclusive{SingleSource}` and R10's ceremony refuses to sign. A controller reads its own chain from the fallback set (R10) and a verifier tries a fallback source before it returns `Inconclusive` (R11), because the holder of the designated key chose the relays the identity's service record names, so a source that record names is a source that key's holder chose. **The set is not a priority order and no rule reads one:** a relay a deployer configured, a relay a peer advertised, and a relay the identity's service record names are all outside the fallback set unless the community relay list carries them.
- The **next set** is the list of at most `MAX_NEXT_SET_SIZE` pre-rotation public keys (§9.18.17) whose commitments the chain fixes (below), with a **next threshold** n. A **reveal** is an indexed signature group over the next set: the preimage names at least n distinct next-set indices, the revealing event carries the public key for each named index, and the signature field carries one slot per named index in index order, each verifying against the revealed key at that index. The **pre-rotation key** P names one member of that set; each is a one-shot authorizer that signs exactly one reveal-authorized event and is then spent and destroyed (R5), and never becomes a root member or any other key. The name is retained; this definition, not the name, governs.
- The **custody type** of a key names the substrate that holds its private half. The enumeration is fixed here, and every other section — the identity spec's custody-migration protocol (`03-identity.md` §3.2.1) included — references it rather than restating it. Its values are the pre-rotation custody methods of §9.7.4.1 item 4 — `OpenPgpToken`, `Hsm`, `SecondaryDeviceKeystore`, `PlatformCloudKeyStore`, `EncryptedOfflineBackup`, `ShamirShares`, `PaperBackup` — together with the operational-key substrates `SecureEnclave`, `AndroidKeystore`, `Passkey`, and `Software`. **A root member's custody type MUST name a substrate that signs raw Ed25519**, so `SecureEnclave`, `AndroidKeystore`, and `Passkey` are forbidden on a root member and a verifier rejects a state-carrying event that lists one there (`Invalid{at_event}`); §9.7.4.1 item 4 states why those three substrates cannot produce the signature R3 requires.
- The **key state** of an identity is: the standing root, each of its members carrying a **custody type** (above), one value per member; every operational key by role (`#active`) and by custody type, one value per key; **every key that has ever appeared on the chain** as a root member or an operational key, each in one of the four conditions of §9.7.1 (`current`, `Superseded`, `Retired`, or `Compromised{from: N}`); the **witness set** — the relays the controller designates to cosign the identity's log head — with two **cosigning parameters**, the **witnessing interval** (`u32` seconds; the interval at which each designated witness re-cosigns the head, and the floor on the controller's self-observation cadence under R10) and the **accountability threshold** (`u8`; the number of cosignatures at which the controller treats its own head as established, which R10's self-observation reads); the **service-key designation** — which operational key signs the identity's service record (`03-identity.md` §3.10.13), named by role and covered by the root signature that covers every other field here; and, for a delegated identifier, the **delegator** (a 32-byte identifier, or the all-zero placeholder for a non-delegated identity). **The key state carries no relay endpoint, no private-state location, and no capability URI.** Every transport and service field lives in the service record instead, which the designated key signs and which ADR-063, the inception-derived key-event-log identity substrate, splits off the identifier record for this reason: a controller changes a relay endpoint by writing a service record under an operational key, appending no key event and warming no root. Each of the fields above is in the inception event's preimage because the identifier freezes that preimage: the initial witness set is what a first-contact resolver reads, custody type is what trust evaluation reads, and delegation must be declared from the first event because a delegated chain's precedence reads the delegator's chain. **The inception fixes the initial value of each field; it does not freeze the field.** Every state-carrying event carries the whole key state, so a later `KeyState` changes the witness set, the two cosigning parameters, the service-key designation, the operational roles, and each key's condition, exactly as R8 describes. The one field the inception freezes for the life of the identity is the delegator, because a delegated chain's precedence reads a different chain and a verifier must know from the first event which chain that is.
- A **state-carrying event** carries the complete key state. Three kinds carry state: the inception event, a `KeyState`, and a `RootRecovery`. **The derived key state at any position is the key state the latest state-carrying event at or before that position carries** (R8); no earlier event contributes.
- A **key-event seal** is a digest, carried by a `KeyState` event, of another identity's key event — the construction by which a delegator anchors a delegate's establishment event. Its preimage is `SHA-256("SCP-KEL-SEAL-V1:" || anchored_event_preimage_digest)` (§9.18.2); one seal anchors one event. A seal anchors key events only; it plays no part in content verification.
- A **pre-rotation commitment** is `SHA-256("SCP-PREROTATION-COMMITMENT-V1:" || pre_rotation_public_key)` over one member of the next set; the chain fixes the list of commitments and the next threshold together. The public key is a fixed-length 32-byte Ed25519 key, so under §9.5.1 it carries no length prefix.
- The **standing commitment** at a position in a chain is the commitment list and next threshold fixed by the latest commitment-fixing event at or before that position — the inception event (R2) or a reveal-authorized event (R4).
- A **reveal-authorized event** carries a reveal against the standing commitment at the event's predecessor: each revealed key's commitment MUST be the member of the standing list at the index the preimage names. **The threshold that reveal is checked against is the next threshold of the standing commitment** — the one fixed alongside the list the reveal consumes — and never the threshold the event itself fixes. The threshold an event fixes governs only the next reveal, against the list that event fixes. Rationale: a reveal checked against its own event's threshold would let a holder of one member of a 2-of-3 standing set name one index, declare its own successor threshold 1, and take the identity over on a threshold the previous controller never set.
- Two chains **diverge** when they share a prefix and each chain carries, at the first position after that prefix, an event the other chain does not carry. The **shared prefix** is the longest common prefix. A **divergent suffix** is the part of one chain after the shared prefix.
- Every key event's signed preimage binds the identifier, the event's sequence (which is its predecessor's plus one, above), the digest of its predecessor event, the event-type discriminator, the signer index list of every signature group the kind carries, and every field a rule in this section reads (the revealed keys, the `standing_root` field, the installed root set and threshold, the key-state snapshot, any key-event seal, the abandonment declaration, and the next commitment list and threshold, where the kind carries them). Every signature an event carries is over that one identical preimage. In the inception event the identifier field and the predecessor-digest field are the all-zero 32-byte placeholder (R13). Rationale: without predecessor binding, a party holding a root could copy the owner's genuine revealed `RootRecovery` bytes onto its own fork at the same sequence and present them as its own; without the index list in the preimage, a relay could strip one of several signatures with no detectable defect; without the declaration in the preimage, a relay could strip the next commitment and substitute abandonment with every named signature still verifying.

**R1 — Closure: only a reveal moves the commitment.** The standing commitment MUST change only in a reveal-authorized event. A verifier MUST reject a chain in which the commitment changes at an event that reveals nothing. Rationale: if a root signature alone could fix a new commitment, an attacker holding the root would fix a commitment to keys the attacker holds, and the owner's later reveal would fail to match.

**R2 — Inception fixes the first commitment and the identifier is bound to the chain.** The inception event installs the first root set and threshold, fixes the first commitment list and next threshold, and carries the initial key state. Its root signature verifies against the root set the inception itself installs — the one event whose signers are named by the event they sign. A verifier MUST reject an inception event that fixes no commitment. A verifier MUST recompute the identifier from the inception event (R13) and MUST reject a chain whose recomputed identifier differs from the identifier under which the chain was served. Rationale: without the recomputation a relay could serve any self-consistent chain, including one whose inception is the attacker's own, under any identifier.

**R3 — Four event kinds; each kind fixes its signature set in a fixed layout; every named signature MUST verify.** A verifier MUST derive an event's kind from the type discriminator in its preimage, never from which signatures it carries, and MUST reject a chain containing an event whose discriminator it does not recognize (`Invalid{at_event}`). The kinds are `Inception`, `KeyState`, `CommitmentRollover`, and `RootRecovery`; these four names, and the condition names of §9.7.1, are the protocol's identifiers, and every SDK binding carries them unchanged as its variant names.

| Kind | Signatures the kind names | Effect |
|---|---|---|
| `Inception` | a root signature by the installed root set | installs the first root; carries the initial key state; fixes the first commitment |
| `KeyState` | a root signature by the standing root | carries a complete key state and any key-event seals; changes no root and no commitment |
| `CommitmentRollover` | a reveal, and a root signature by the standing root | fixes the next commitment, or declares abandonment; changes no root and carries no key state |
| `RootRecovery` with `standing_root: CoSigns` | a reveal, a root signature by the installed set K′, and a root signature by the standing root | installs K′; carries the complete post-recovery key state; fixes the next commitment |
| `RootRecovery` with `standing_root: Lost` | a reveal, and a root signature by the installed set K′ | the same effect, without the standing root's signature |

**The signature set closes by construction.** Each kind — and for a `RootRecovery`, the kind together with its `standing_root` value — fixes which signature groups the event carries and in what order; within each group the preimage's signer index list fixes the slot count, so the signature field carries exactly one 64-byte slot per named index, groups in the order the kind's table row lists them, and its length is a function of the kind and the index lists. Any other bytes in the signature field are a copy-level defect. An event carries no signature its kind and index lists do not name. Endorsements by third parties and cosignatures by witnesses are **separate signed objects over the event's preimage digest**, never carried on the event copy, and travel a channel the witness protocol of §9.7.4.3 names, which that section does not yet carry. Rationale: a signature carried on the copy can be stripped or stuffed by any relay with no detectable defect, so evidence that rides the copy is neither reliably present nor reliably absent, and an unbounded signature field is a verification-cost amplifier; the index list in the preimage is what lets a threshold be checked over a set of more than t members while the layout stays closed.

A `RootRecovery` carries a required field `standing_root` with exactly two values, `CoSigns` and `Lost`, bound in the preimage. The value declares which set the event carries, so a `RootRecovery{CoSigns}` whose root signature is missing or fails to verify is a copy-level defect and never a `RootRecovery{Lost}`; the declaration in the preimage, not the presence of a signature, says which signatures the event names. **`Lost` is a controller obligation and no verifier checks it.** The signing quorum MUST establish that fewer than t members of the standing root are reachable before it declares `Lost`; where the SDK itself holds at least t members — the personal 1-of-1 case, and any case where one device holds the quorum — it MUST refuse, with a typed error, to sign `standing_root: Lost`. That refusal is the one mechanical realization of the obligation, and it cannot run for an organization whose five root members sit in five separate substrates, so a party's witness policy reads `Lost` as the controller's declaration and never as a checked fact. The `CoSigns` signature is evidence a party's witness policy reads (R6, Pin A); it is not a rank. A `RootRecovery` also carries the revealed keys, the installed root set K′ and its threshold with a root signature by K′ as proof of possession, the complete post-recovery key state (definitions), and the next commitment (R4); no revealed key is ever installed, and no root member is ever the preimage of any commitment, because K′ is generated fresh and the commitment names separate keys. A `CommitmentRollover` carries no key state: it changes the commitment, or declares abandonment, and nothing else.

**Every indexed signature MUST verify against the key at its index**: each revealed key's signature against the revealed public key at that index, each standing-root signature against the standing root member at that index, and each installed-root signature against the installed set's member at that index; the inception's root signatures verify against the set the inception installs. A signature that does not verify is absent. Two classes of invalidity follow. A **copy-level defect** — an indexed signature, at an index the set contains, that is absent or fails to verify; a corrupted byte; or extra bytes in the signature field — is producible by any relay with no key, so the verifier discards that copy, treats the position as unserved under R11 (`Inconclusive{CopyDefect}`), and never demotes the suffix or records anything against the identity; an intact copy from another source supersedes the mutilated one, and events are identified by preimage digest for that purpose. An **author-attributable defect** is signed content, so the verifier rejects the chain at that event (`Invalid{at_event}`, R14). The author-attributable defects are:

- a signer index list naming fewer than t root members, where **t is the threshold of the set that group indexes** — the standing root's own threshold for a standing-root group, and the installed set K′'s own threshold for an installed-root group, so a `RootRecovery{CoSigns}` carrying a 3-of-5 standing group and a 1-of-1 installed group satisfies this bullet on both; or a signer index list naming fewer than n next-set members, where n is the standing commitment's next threshold (definitions);
- a repeated index in any signer index list;
- a signer index that names no member of the set the group indexes — the index is bound in the preimage, so only the signer could have written it;
- a root set or a next set whose members are not pairwise distinct, or a commitment list whose entries are not pairwise distinct;
- a threshold t outside `1 ≤ t ≤ |root set|`, or a threshold n outside `1 ≤ n ≤ |commitment list|`;
- a sequence that is not its predecessor's plus one, or an inception event whose sequence is not zero (definitions);
- a revealed key whose commitment is not the standing list's member at the named index;
- a state-carrying event listing one public key more than once, whatever conditions the two entries carry;
- a state-carrying event listing a custody type on a root member that names a substrate which does not sign raw Ed25519 (definitions);
- an unrecognized discriminator;
- a next threshold n, fixed by the event, lower than the threshold of the root set standing **after** that event — the installed set K′'s threshold on a `RootRecovery`, and the unchanged standing root's threshold on every other kind, because the reveal that consumes this commitment will be checked against whichever root stands then. Rationale: a reveal-authorized event is as strong as the weaker of the two thresholds it stands between, so a 3-of-5 organization that fixed a 1-of-1 next set would be taken by whichever officer held that one pre-rotation key. Requiring n ≥ the standing root's threshold makes the recovery path as strong as the root it recovers, and a controller that deliberately installs a weaker root gets a next threshold measured against the root it actually installed;
- a state-carrying event whose service-key designation names a key that same snapshot does not list `current`, or names no key at all. A `RootRecovery` therefore installs at least one operational key, which R10's ceremony already generates. Rationale: the designation is what a relay checks a write against (§9.10.12), so a designation naming a retired or absent key leaves the identity unable to publish its own recovery;
- a witnessing interval below `MIN_WITNESSING_INTERVAL` (§9.18.17). Rationale: an interval of zero makes R10's self-observation an unbounded fetch loop;
- **a nonzero accountability threshold, until §9.7.4.3 carries the witness protocol.** No section states how a witness cosigns a head, so no controller can satisfy a threshold of one and no verifier can check that it was satisfied; a state-carrying event that carried a nonzero value would put every reader in a permanent alert it cannot clear. §9.7.4.3 removes this bullet when it lands, and R10's self-observation reads the field's zero value until then;
- **a state-carrying event listing more than one key `current` in any single operational role.** Rationale: a role names one signer. Two keys `current` in `#active` give the identity two key-continuity fingerprints, so a peer comparing fingerprints reads a false MITM (§9.11); they let two service records verify at once (`03-identity.md` §3.10.13); and a second key slipped into the role keeps attesting after the controller rotates the first;
- **a state-carrying event that installs a key which appeared earlier on the same chain as a revealed next-set key.** Rationale: R4's key-uniqueness invariant counts installations, and a revealed pre-rotation key was never installed, so without this bullet a surviving Shamir share or paper copy of a spent pre-rotation key becomes the identity's live signer and no chain diverges to signal it;
- **an event fixing a commitment whose preimage is a key that same event installs.** Rationale: R4's commitment-freshness invariant reads the keys at or before the fixing event, and an event that commits to a key it also installs makes one compromise yield both the live root and the reveal that would recover from it;
- **a key state whose `delegator` field is nonzero, until ADR-064, the cooperative-delegation model, lands.** No section states how a verifier fetches the delegator's chain, finds the key-event seal anchoring this chain's establishment events, or ranks a delegated chain, so a verifier presented with a nonzero delegator has no rule to apply. The preamble of this section cites this bullet where it defers delegated precedence, and ADR-064 removes it;
- a violation of any R4 or R8 obligation.

**The criterion that separates the two classes** is whether a relay holding no key could have produced the defect: a defect a keyless relay could produce is copy-level, and a defect only the signer could have produced — because the preimage binds it — is author-attributable. The two lists above are the indicators a verifier applies; where a new defect fits neither list, the verifier decides it by that criterion. Authorization is the signature by the revealed private keys and never the reveal alone: a revealed public key is public the instant the event appears.

**R4 — Every reveal-authorized event fixes the next commitment or declares abandonment, under two closed invariants.** A reveal-authorized event either fixes the next commitment list and next threshold — the controller MUST generate those keys in a substrate satisfying §9.7.4.1 item 3a before it signs (R10 states when) — or carries an explicit **abandonment declaration** in place of a commitment and generates no next set. **Only a `CommitmentRollover` co-signed by the standing root may declare abandonment**: the party retiring an identity holds its root, and a controller whose root is lost recovers first (a `RootRecovery{Lost}` installs K′) and abandons under a second reveal co-signed by K′. A reveal alone cannot abandon. An event that fixes no commitment and declares no abandonment is invalid. **Abandonment is terminal:** after an event that declares abandonment, no further key event on that chain is valid, and a verifier MUST reject any event whose predecessor chain contains one. The derived key state after abandonment is the state the latest state-carrying event before it carries, and the abandoning event changes nothing in it. **The abandoning controller owns the boundary:** before it publishes the abandoning rollover it MUST issue the MLS Update of §9.12 step 2 in every context it belongs to, and each of those Commits is the abandonment boundary in its context (§9.7.1). **In a context the controller cannot reach, there is no boundary, and §9.7.1 governs.** The boundary for a key in a context exists iff that context's Commit history records a retirement Commit from the identity for that key (§9.7.1), and an abandoning controller that never reached the context left no such Commit there. The residual, stated plainly: that context's members keep verifying content under the abandoned identity's operational key until the controller reaches the context and issues the Update, and no member of it learns of the abandonment from the log alone. A controller that regains reach re-joins the context manually and issues the Update then (§9.12 states the step ordering). Content signed before abandonment verifies against the final state under §9.7.1; the abandoning Commit is the boundary for every key the final state lists `current`, so those keys verify nothing after it. **After a relying party confirms an abandonment, it MUST treat every UCAN the identity issued as revoked, every attestation it issued as expired, and every sender key it holds for the identity as retired**, and MAY then remove the identity from a context and withdraw its standing. **Confirmation before social action, for every adopted takeover and every abandonment:** a relying party MUST NOT act socially on a chain it adopted — remove an identity from a context, revoke its standing, treat it as abandoned — until it has confirmed that chain's head from a source the identity's service record does not name, because the holder of the designated key chose the relays that record names (definitions, fallback set). Two invariants hold over the whole chain, and a verifier MUST reject the event that breaks either: **key uniqueness over installation** — a public key is **installed** by at most one event on a chain and holds one role there (a root member or an operational key), and listing an already-installed key in a later state-carrying event's snapshot is not an installation, so a snapshot that re-lists every prior key breaks nothing; and **commitment freshness** — a fixed commitment equals no commitment fixed earlier on the chain, and equals the commitment of no key that appears on the chain at or before the fixing event, the keys that same event installs included. Rationale: a chain whose standing commitment has been consumed and neither replaced nor declared abandoned has no recovery path and no terminal state; a key that reappears or a commitment that repeats would let a spent or stolen key satisfy a later reveal; abandonment authorized by a reveal alone would let anyone who ever obtained enough of one next set kill a live identity whose root is intact; and a boundary nobody issues is a boundary nobody can read.

**R5 — The controller destroys the spent pre-rotation keys.** After the controller has retained the signed event (R10's retention invariant), the controller MUST destroy **every private key of the next set whose commitment list the reveal-authorized event superseded — every member, whether the reveal named it or not** — from every custody location and backup medium it controls, for a `RootRecovery` and a `CommitmentRollover` alike, and MUST NOT destroy them before that retention. A reveal that names n of a longer list leaves the unnamed members holding a commitment the shared prefix still carries, so a member left alive lets whoever later obtains it fork before the superseding event and reveal the same standing commitment; §9.7.4.1 item 8's retention obligation ends for the whole set at that same event, so no rule asks the controller to keep one. R5 reaches only the controller's own copies: a Shamir share held by a contact, a paper mnemonic already photographed, and a cloud key store's historical snapshot are outside its reach (§9.7.4.1 item 4's destructibility axis), so a controller using a non-destructible medium cannot fully comply and MUST be warned at custody selection. Rationale: a spent key that survives can join a second reveal of a commitment already consumed, which under R6 makes the identity contested at that fork.

**R6 — Fork precedence over key material, and the slot a witness policy fills.** A verifier first evaluates validity (R1–R4) over each chain in full; a chain invalid at any event is `Invalid` and is not ranked. When a verifier holds two valid chains that diverge from a shared prefix, it MUST rank them as follows. Let C be the standing commitment at the shared prefix. On each divergent suffix, the verifier locates the first event that reveals C; at most one such event exists per suffix, because R1 makes C unique on the shared prefix, a reveal consumes it, and R4 forbids fixing it again. The verifier ranks each suffix:

1. the suffix carries an event that reveals C;
2. the suffix carries no event that reveals C.

A rank-1 suffix beats a rank-2 suffix, and the winning chain supersedes the losing chain in its entirety. **Two rank-1 suffixes do not resolve: the identity is contested (R7), and no property of either event breaks the tie**, because over key material the two reveals are indistinguishable — both parties held the pre-rotation keys. A verifier MUST NOT decide a divergence by head sequence or by the first event after the shared prefix. When a verifier holds more than two chains, it ranks every pair against the standing commitment of that pair's own shared prefix; the winner is the chain that wins every pairwise comparison it is party to; the identity is contested when no such chain exists, and the composite tie is terminal if any pair ties at rank 1 (R7).

- *Pin A.* **Rank reads one property of a suffix — whether it carries an event revealing the shared prefix's standing commitment — and nothing else. A root co-signature on a revealing event, whether on a `CommitmentRollover` or on a `RootRecovery{CoSigns}`, is evidence a party's witness policy reads and never a rank.** This is the criterion; no case-local reasoning below adds to it or narrows it.
- *Pin B.* Once a suffix carries a C-revealing event, its rank is fixed and does not change when the suffix is extended. A suffix with no C-revealing event is rank 2 until one appears (R7's pending tie). A reveal on a suffix that consumes a commitment the suffix itself fixed confers no rank, because the shared prefix never committed to those keys; without this clause a party whose recovery installed its own root and its own commitment could reveal that commitment on its own suffix and claim rank 1.

**Key material cannot resolve a contest between two reveals of one commitment; the witness layer can.** A witness that cosigned the owner's head refuses to cosign a fork anchored behind it under its consistency rule, and a root co-signature on a revealing event is further evidence a policy weighs. **A party applying a witness policy over a set it recognizes as independent of the root holder MAY, on a contested divergence, adopt the suffix that set has cosigned; a party applying no such policy holds the key-material verdict, which is contested.** The recognized set MUST NOT be derived from the snapshot of any divergent suffix, because that suffix's author named it; a policy reads the set as it stood at the shared prefix. Detection by the witness layer is the mandatory base of that layer; a witness gate is a relying party's opt-in policy and never a condition of an identity's resolvability. §9.7.4.3 does not yet carry the witness protocol; until it does, every rank-1 tie is terminal for every party.

Rationale for the two comparisons this rule replaces: a comparison of the first event after the shared prefix lets the party that chooses the fork point choose which events are compared, so an attacker who forks among the owner's ordinary key events wins before the owner's recovery is read; a comparison of head sequences lets the party that appends the most events win.

**R7 — Ties and the contested verdict.** Equal rank resolves no winner over key material, and the identity is **contested**. The tie's class is a function of the tied rank: a tie at rank 1 is **terminal by key material** — C is consumed on both suffixes, so no key event on either suffix changes the comparison; a tie at rank 2 is **pending** — neither suffix has revealed C, and a later reveal on one suffix decides the divergence under R6, while a later reveal on both escalates the tie to rank 1 and terminal. A party's witness policy MAY resolve a tie of either class for that party (R6's slot). For a contested identity a verifier MUST return the `Contested` verdict (R14), which carries the tie class, the digests of every tied head, the digest of the shared prefix's head, the fork position, and R9's residue count; MUST NOT adopt any tied suffix as the **`current`** key state; and MUST retain every tied head and suffix in its retained set as evidence, where R9's bound and its rank-eviction rule fix what that set holds. The verifier MAY use the shared prefix's key state — the state both suffixes agree on, which the verdict's shared-prefix head identifies — as the verification basis for content a context placed before the fork; it verifies nothing after that, and it MUST NOT serve that state as `current`. **"Before the fork" in a context anchors to the member's own observation:** content is before the fork when the member accepted it under an epoch no later than the last Commit that context observed from the identity **before the member first observed any divergent suffix of that identity**. A member that observed no such Commit — because the identity issued none in that context before the divergence reached it — verifies nothing for that identity in that context and reports `Invalid{no_prefork_basis}`, which is the fail-closed direction. Anchoring to the fork position instead would name a Commit that exists only when the fork position happened to retire a key, and three members would then read three different Commits for one message. Criterion for what a tie proves: a rank-1 tie proves that a threshold of the next set signed two divergent events; a rank-2 tie proves that the standing root signed two divergent suffixes. Indicator, not criterion: two parties holding the keys is the usual cause, and one holder with two devices also produces one. When R6 later resolves a divergence that a verifier had recorded as a rank-2 tie, or the tie escalates to rank 1, the verifier MUST retire the rank-2 equivocation record and MUST NOT count it against the identity. §9.11's clearing rule reads that retirement, and §9.11 is where the rule that clears a standing is stated. Rationale for refusing the shared prefix's state as current: if the root was compromised before the fork point, the shared prefix already carries the attacker's events.

**R8 — Key state is the latest state-carrying event; nothing is voided; nothing is omitted.** The derived key state at any position IS the key state the latest state-carrying event at or before that position carries; no earlier event contributes, and a verifier applies no diff, no undo, and no voiding. A `RootRecovery` therefore replaces the entire key state in one event: every operational key an attacker installed, every condition an attacker asserted, every witness-set and service-key change an attacker made, is absent from the recovery's **roles** and so is not `current` after it. **Every key the chain installed appears in the snapshot with a condition.** Every key that any event at or before the snapshot's own position installed — as a root member or as an operational key, whoever authored the installing event — MUST appear in the snapshot in exactly one of the four conditions of §9.7.1, and a state-carrying event that omits one is malformed: a verifier MUST reject it (`Invalid{at_event}`). A key the recovering controller believes an attacker installed is listed `Compromised{from: N}`, never left out. Each key appears **once**; a snapshot that lists one public key twice, under two conditions or under the same one, is malformed on the same terms. Rationale: nothing is voided and nothing is omitted, so a compromise is asserted and never implied by silence — a controller that could drop a key by leaving it out would repudiate every signature that key ever made, which is the outcome §9.7.1 promises cannot happen, and a verifier reading a snapshot that lists one key twice would resolve the same key to two conditions. The recovery's operational-key roles replace the derived roles in full: an operational role the snapshot does not name is not `current` after the recovery. **The same replacement governs every other key-state field**, so a `KeyState` changes the witness set, the witnessing interval, the accountability threshold, and the service-key designation by carrying new values for them, and R3 bounds the two cosigning parameters wherever an event carries them. A `Compromised{from: N}` entry carries a position in this log, bounded N ≤ the sequence of the event that carries the entry; a verifier MUST reject an entry whose N exceeds that. **N has exactly one reader outside this section**: the log-anchored evidence class of §9.7.1, which reads N in the test that section states for an artifact signed under a key the state lists `Compromised`. No other content rule reads N — §9.7.1's content class orders content by the context epoch and never by N — and no rule in this section rejects a controller's event on account of content. A `CommitmentRollover` carries no key state and changes the derived state in no way; the derived state after an adopted rollover is the state of the latest state-carrying event before it, which after a divergence may be an event on the shared prefix. Chain validity under R1–R4 is evaluated over the full chain with every event present. Rationale: an attacker holding the root who appends `KeyState` events to the one genuine log produces no divergence, so R6 never runs, and only a full replacement of the roles removes what it installed; a rule that voided by boundary needed an expanding list of exemptions; and a controller that could omit any key by silence could repudiate its own history, which the listing obligation forbids for every key the chain installed. A state-carrying event costs O(keys) bytes, a few kilobytes on a log whose key events are rare.

**R9 — Retention of evidence, the store, and the retention bound.** A verifier MUST NOT bound the suffix it retains at its last reveal-authorized event, because a party holding a spent pre-rotation key can anchor a fork before that event (R5).

**The store, and what a slot holds.** A validating relay keeps one slot per **(routing id, divergent suffix)**. Two chains that are prefix-related are one chain for this purpose and collapse into one slot, which holds the longer of them; two chains that diverge (definitions) occupy two slots, whether or not their heads stand under the same root set. Keying the slot on the root set alone would put every divergence that has not yet installed a new root into one slot, and the write rule would then hand that slot to whichever party published first — the owner's own two devices in a rank-2 tie, or a root thief who forked at an ordinary `KeyState` — so no verifier would ever hold both chains and R6 would never run. **A slot holds the full chain from the inception event to its head**, not a head alone, and a relay serving a head serves every predecessor of that head, because R6 ranks chains and a slot that held only heads would leave a verifier unable to rank the head it was served. **The relay's slot set is the same structure this rule tells a verifier to keep** — at most `MAX_RETAINED_SUFFIXES` divergent suffixes per identity, evicted by the rank rule below — so a relay and a verifier hold the same evidence under one rule. `03-identity.md` §3.10.2 states the relay's validation procedure and cites this paragraph for the slot key, the chain-holding property, the write rule below, and the eviction rule; it restates none of them, and §9.10.12 states the frame's bytes and cites §3.10.2 for the procedure.

**The write rule reads the assembled chain, and a slot is an ordered sequence of frames.** A relay stores, per routing id, the events every accepted frame carried, and each slot is one maximal chain through them. **A relay accepts a frame whose first event's predecessor digest names an event it already holds at that routing id**, verifies that frame's events under R2 and R3 against the standing root the assembled chain carries at the named position, and adds them to the store. Three outcomes follow, and exactly one applies to any frame:

1. **The named event is the head of a slot.** The frame's events extend that slot, and the slot's chain grows by them. A publisher whose chain outgrew one frame publishes segment two this way (`03-identity.md` §3.10.5 step 3).
2. **The named event is interior to a slot's chain, and the frame's first event differs from the event that slot already holds at the next position.** The two chains diverge (definitions) at that position, so the frame's events form a second divergent suffix over the shared prefix, and that suffix occupies its own slot under the admission and eviction rule below. The relay stores the prefix once and both suffixes over it.
3. **The frame's range lies inside a slot's chain and its bytes are identical to the events that slot holds there.** The frame is an idempotent TTL refresh and changes no slot. A frame whose range lies inside a slot's chain with different bytes at any event is case 2, not a replacement: a relay replaces no event it already holds.

**Only a frame whose first event is the inception event opens the routing id's first slot.** The relay verifies that frame from the inception event under R2 and R3, which is what establishes the standing root every later frame is verified against; a relay holding no event at a routing id has no position a predecessor digest could name, and it rejects a frame that names one. A relay rejects a frame whose first event's predecessor digest names no event it holds, and the publisher's remedy is to publish the intervening segments first, in order.

**Why a flood of slots takes no identity.** Every event a slot holds stands under a root the relay verified from the inception event forward, because the store begins at inception and every later frame is verified against the assembled chain's standing root (above). A party that opens many slots by revealing the standing commitment many times has put every one of those suffixes at rank 1 and made the identity contested by R7 whatever the relay stores; a party that opens slots without revealing produces rank-2 suffixes, which the eviction rule below discards first. A flood of slots is therefore a symptom of an already-contested or already-taken identity, never a way to take an intact one.

**A chain is served in segments, and the chain has a ceiling.** A frame carries a **contiguous segment** of one chain: its `value` names the segment's first and last sequence, and the events between them in order. A relay serves a slot's chain as an ordered sequence of frames covering inception through head, and a resolver assembles the segments and verifies from the inception event, or from a state-carrying event on that chain it already holds. A chain carries at most `MAX_KEY_EVENTS_PER_CHAIN` key events (§9.18.17), and a verifier rejects a chain that exceeds it (`Invalid{at_event}` at the first event past the ceiling). The ceiling exists because R8 makes every state-carrying event list every key the chain ever installed, so a chain's bytes grow with the square of its key-event count; the ceiling states where that growth stops rather than leaving an identity to discover it as an unpublishable frame. **One event MUST still fit one frame**, and §9.18.17 states the arithmetic that keeps the largest event on a full chain inside the `value` bound of §9.10.12. Snapshot entries themselves stay complete: segmentation splits a chain across frames and omits no event and no entry, so R8's listing obligation is untouched.

**The retention bound and its eviction rule.** A verifier retains at most `MAX_RETAINED_SUFFIXES` divergent suffixes per identity (§9.18.17: 8). A candidate that would exceed the bound is **admitted**, and the verifier evicts the retained suffix of lowest rank, breaking a tie among equal ranks by evicting the suffix it observed first. **Rank here is pairwise, under R6's composite rule**: the holder ranks every pair of retained suffixes against the standing commitment of that pair's own shared prefix, and within a pair a suffix is rank 1 when it carries an event revealing that commitment and rank 2 otherwise. Eight suffixes form up to twenty-eight pairs and as many shared prefixes, so no single commitment ranks them all and no one chain serves as the reference the others are measured against. **A rank-1 suffix is never evicted.** When every retained suffix is rank 1 and another rank-1 candidate arrives, the verifier keeps the retained set and returns `Contested{…, residue: n}`, where n counts the rank-1 candidates it could not retain — the identity is contested either way, and the residue tells the consumer that more tied suffixes exist than the verdict enumerates. Each eviction records the evicted head's digest so that a re-served copy is recognized as one the verifier already ranked. A validating relay, which verifies chains under R2 and R3, applies this same rule to its slots for one routing id, and it ranks **pairwise** under R6's composite rule: every pair of slots against the standing commitment of that pair's own shared prefix. A relay adopts no chain — adoption is the resolver's act (R6, R14) — so a rule that ranked each slot against one chain the holder had adopted would have no input at a relay, and two relays would evict different slots from the same set. R7's obligation to retain every tied head, and R14's persistence obligation, are scoped to the retained set. Rationale for the value: two devices plus several attacker forks fit with margin; the bound caps the pairwise comparison a flood would otherwise drive quadratic. Rationale for admitting rather than refusing: a bound with no eviction rule makes a flood the winning move, because a party that publishes eight rank-2 forks first would fill every slot before the owner's rank-1 recovery arrived and the recovery would never be ranked. Indicator, not criterion: key-event logs are short, so a verifier that retains in full every chain it holds satisfies R11's evidence obligation with no fetch.

**R10 — The controller's procedure.**

*Which event to sign.* No ordering exists between the events; the controller signs the one row that matches its situation:

| The controller… | signs |
|---|---|
| holds a threshold of its root and must retire it — because any root-signed event on its chain exists that it did not author, fork or not; because it asserts a compromise; or for any reason it must move the root, including a custody substrate being decommissioned | `RootRecovery{CoSigns}` |
| holds a threshold of its root, trusts it, and suspects only a pre-rotation key copied | `CommitmentRollover` |
| has lost its root | `RootRecovery{Lost}` |
| is retiring the identity permanently and holds its root | `CommitmentRollover` declaring abandonment (R4), after the §9.12 step-2 Update in every context |
| finds its identity contested and wishes to retire it | `RootRecovery{CoSigns}` on its own suffix first, retiring the contested root set, then abandonment under K′. The order forecloses a copy holder's extension past the commitment K′ fixes and ends no contest (§9.7.4.1's failure-mode table, the two-phase row) |

A reveal-authorized event puts its suffix at rank 1 against any divergence whose shared prefix's standing commitment it reveals (Pin B); the choice among rows is a choice of what the event does to the key state and what evidence it carries. The SDK MUST treat any reveal-authorized event on its identity's chain that it did not sign, and any root-signed event it did not author, as evidence of compromise and alert at maximum severity; it MUST be able to extend a suffix the controller authored even after its own verifier adopted or contested a competing chain — the SDK extends its own suffix as the controller and, as a relying party on its own identity's state, holds the `Contested` verdict like any other party; and when its own identity is contested it MUST tell the human which suffix a witness policy would resolve for. A controller SHOULD roll over on suspicion, not on a schedule: every rollover mints a spent key whose later leak contests the identity, so a schedule multiplies that exposure with no threat-driven gain.

*Self-observation.* The SDK MUST fetch its own identity's log at a stated cadence — no less often than the witnessing interval the key state names, and on every launch — from at least one relay in the fallback set (definitions), and MUST treat an inability to complete that check as an alert, not as silence. **The accountability threshold has one reader, and it is this sentence:** the controller treats its own head as established once it holds at least that many cosignatures for it from the witness set its key state names, and it alerts the human while it holds fewer. R3 rejects a state-carrying event carrying a nonzero threshold until §9.7.4.3 lands, so every key state carries zero today and no controller holds an alert it has no means to clear. The controller changes both cosigning parameters by a `KeyState` (R8), so neither value is fixed for the life of the identity.

*Before composing a snapshot.* The controller MUST hold its chain from the inception event, obtained from at least one relay in the fallback set (definitions); MUST enumerate **every key any event at or before the snapshot's position installed**, with each key's custody type and the condition the snapshot will give it, so that the snapshot lists each one exactly once (R8); MUST diff the chain's current witness set and service-key designation against the inception's or against a pre-compromise record it holds and surface every entry introduced at or after the asserted N; and MUST diff its service record's relay list against a pre-compromise copy it holds, because an attacker holding the designated key rewrites that list without touching the log (§9.6.3). **The refusal splits by verdict.** On `Inconclusive` the controller MUST refuse to sign, with a typed error, because it cannot see the events whose keys R8 requires it to enumerate. On `Contested` the controller refuses only when it cannot identify which suffix it authored; when it can, it composes over that suffix and signs, which is what the paragraph below tells the SDK to keep doing. A blanket refusal on `Contested` would lock the controller out of the first row of the table above, whose whole premise is a root-signed event some other party wrote onto the chain.

*Device boundary.* A reveal-authorized event MUST be produced on a device, and its successor keys — K′, the operational keys the snapshot installs, and the next set — generated in custody, that the controller has established the asserted compromise did not reach. When the compromise reached a platform account (a passkey or cloud-keystore account, a device-management enrolment, a restore image), the controller MUST create a fresh platform account and MUST NOT restore any state from the compromised one before proceeding; a controller that cannot establish the boundary by that or another stated means MUST NOT proceed. The controller MUST confirm, before the reveal signs, that the event carries **the commitment list of the keys it just backed up, the next threshold that list carries, the K′ set and the root threshold it installs, and whether the event declares abandonment** — every field whose substitution changes who controls the identity afterwards — on a device with a display that is not the assembling device, or by comparing a displayed digest of the event against one the pre-rotation substrate computes. **What that confirmation establishes, and what it does not.** It binds the bytes the signing substrate consumes to the event the human read, which closes substitution between the assembling device and the token, because a hardware token with no display signs whatever it is shown. It establishes nothing about where the committed successor keys came from: the human is reading values the assembling device produced, so a compromised assembler that generated K′ and the next set itself passes the check. The provenance of those keys is the device boundary of this paragraph, and nothing else. The recovery entry point names the fresh custody as a required input with no default and no fallback to the daily provider.

*Ceremony order.* Enumerate (above); for an event that fixes a commitment, generate the next set under §9.7.4.1 items 1, 3a, 4, and 5b–5d — an abandoning event generates none; for a `RootRecovery`, generate K′ and the operational keys under the device boundary; for an abandoning rollover, issue the §9.12 step-2 Update in every context (R4); **persist the recovery handle carrying the composed preimage (below); sign** — each pre-rotation key signs where it resides and is never imported into operational custody; publish; retain; destroy. **The persist precedes the signature**, so no window exists in which a signed reveal exists that no handle names: a controller that crashed between signing and persisting would resume by composing a fresh next set, and its second event would reveal the standing commitment a second time and contest its own identity permanently. Because Ed25519 is deterministic, a resume that signs the persisted preimage produces the byte-identical event the first attempt would have produced, so a resume mints no second reveal. **Retention is the invariant that makes destruction safe:** the controller MUST durably retain the byte-identical signed event as the head of its own chain BEFORE it destroys the spent keys (R5). **Confirmed publication** is durable self-retention together with acceptance of the event by at least one relay in the fallback set (definitions) — an entry of the community relay list that the identity's own service record does not name, so no holder of the designated key chose it — and the controller MAY publish to any additional relay at any time. **The recovery replaces no service record**: the record is a separate object under a separate key, so a controller whose recovery designates a new service key MUST write a fresh service record under that key before its relay list is authenticated again (§9.6.3). **The fallback set is what the definitions section states it is, and it can be empty** — an identity whose service record names every entry of the community relay list of §18.5.1 leaves no relay outside that record. **The SDK MUST refuse, with a typed error, to compose a reveal-authorized event when it can reach no source in the fallback set**, whether because it reached none or because the set is empty, because a controller that cannot read its own chain from a source an attacker did not choose cannot establish what it is recovering from, and a ceremony that could never reach confirmed publication would consume the standing commitment for nothing. R11's verifier obligation reads the same floor. **The ceremony completes at confirmed publication plus destruction.** The controller then submits the event to the witness set its snapshot names, and that submission is a Layer-B step outside the handle: it never gates destruction and never gates completion, because an identity's resolvability never depends on a witness (the witness layer detects; a witness gate is a relying party's opt-in policy) and §9.7.4.3 does not yet carry the witness protocol.

*The recovery handle.* The controller MUST durably persist a typed recovery handle BEFORE it signs the event, and phase 1 begins at that persist. The handle is a tagged union over two axes — the phase (composed and persisted but not yet signed; signed but no publish sent; a publish sent, acknowledged or not; published and confirmed but the spent keys not yet destroyed) and the event's kind of continuation (`FixesCommitment` or `Abandons`) — and each variant carries only what its resume consumes: the composed preimage in every phase, the byte-identical signed event from the second phase on, the spent keys' custody handles in every phase before destruction, and, in a `FixesCommitment` variant only, the next set's custody handles and the expected commitment list so a resume re-checks it; the `Abandons` variant has no next-set field by construction rather than by absence. Exactly one named accessor loads a pending handle after a restart, and exactly one resume entry point consumes the handle by value and continues from its phase — signing the persisted preimage in the first phase, and re-signing nothing in any later phase.

*Abort.* **Abort is available in phase 1 alone — composed and persisted, not yet signed — and in no phase after the signature.** In phase 1 it consumes the handle by value and MUST destroy the composed preimage and the next set the ceremony generated, and it leaves the standing commitment unconsumed and the chain unchanged, which is the guarantee abort carries and the only place that guarantee is true. From the signature onward the controller resumes from the handle and recomposes nothing.

**The boundary abort respects is the SIGNATURE, not the publish.** R3's own criterion is that the signature is the authorizing act, so a signed reveal-authorized event has consumed the standing commitment whether or not it left the device. A controller that destroyed a signed event believing the commitment unconsumed would later reveal that commitment a second time and contest its own identity permanently under R7, and the surviving copy needs only to reach one relay: a lost acknowledgement, an operating system's swap file, or a device backup is enough. **The remedy for a wrong device-boundary establishment discovered after signing** is not abort: the controller publishes the signed event E1, then signs a further reveal-authorized event under the commitment E1 fixed, generated inside the boundary it meant to establish. That path costs one extra event on the chain and consumes one next set; abort at that point would cost the identity. From the signed state the controller's paths are: complete the ceremony from the handle, or extend its suffix under the table above. Never abort.

**R11 — Divergence is a positive finding.** A candidate head is **on the accepted chain** when either chain is a prefix of the other. A candidate head is **divergent** when the verifier holds both chains back to a common ancestor and they diverge (definitions). A candidate that is neither — because the events linking it to the accepted chain were not served, or because a served copy failed verification as a copy-level defect (R3) — is **inconclusive**: the verifier holds its baseline, records nothing, and returns the `Inconclusive` verdict (R14), which names the candidate head, the accepted head, the missing sequence range, and every source that failed to serve the link; before returning it the verifier MUST have tried at least one relay in the fallback set (definitions). R9's retention bound never produces this verdict, because R9 admits the candidate and evicts by rank instead.

**First contact takes two relays under distinct declared operators, one of them outside the identity's own service record.** A verifier holding no accepted baseline for an identifier MUST obtain that identifier's chain from at least two relays **under distinct declared operators** (definitions, community relay list), of which at least one is in the fallback set — an entry the identity's own service record does not name. Two entries the community relay list declares under one operator identity are one source for this floor, and the verifier counts them once. **It settles the chains those relays served under R6, R7, and R12, never by sequence:** where two chains are prefix-related, the longer extends the shorter and the two are one chain (R12); where two chains diverge, the verifier ranks them (R6) and reports a tie as `Contested` (R7). Comparing head sequences across the sources would hand a root thief every first contact, because the thief appends events at will and R6 exists to refuse exactly that comparison. **When it can reach no second relay, the verdict is `Inconclusive{SingleSource}` (R14) and the verifier adopts no head**, and the same verdict follows when the identity's service record names every bootstrap relay and leaves the fallback set empty, and the SDK reports that cause rather than a generic failure, so the human sees that the identity was not resolved rather than that it does not exist. Rationale: a single relay can always serve a genuine prefix truncated before the event the reader most needs — the `KeyState` that retires a stolen key, or the recovery that replaced a root. Such a prefix forks nothing, so R6 never runs; it verifies clean under R2 and R3; and a first-contact verifier holds no baseline, so R12 has nothing to compare. Neither the chain's own rules nor any relay-side gate detects it, because a relay-side gate is code an untrusted operator omits. Two relays are what a first-contact reader has instead, and a later reader holding a baseline has R12 and R6. A witness that cosigns the log head is what would let one relay suffice, and §9.7.4.3 does not yet carry the witness protocol. A verifier MUST record equivocation evidence only from two chains it holds in full back to their common ancestor, and only when R6 resolves them as a tie (R7). Rationale: a single relay that withholds linking events, or serves a mutilated copy, could otherwise cause a verifier to record a durable verdict against an honest identity.

**R12 — Sequence governs the accepted chain only.** For a candidate head on the accepted chain, a verifier **discards** a head at a sequence strictly lower than the highest it has accepted, changing no stored state and returning `Discarded{accepted_head}` (R14), and an equal sequence with an identical head confirms the baseline (`Confirmed`). A discarded stale candidate is not a resolution outcome: the verifier stays on the baseline it already held, so a consumer that treated a discard as a completed resolution would run its next check against a baseline the candidate did nothing to refresh. A candidate whose chain is neither a prefix of the accepted chain nor extended by it is classified under R11 and decided under R6 and R7. A divergent candidate's head sequence decides nothing. Adopting an R6 winner MAY lower the accepted head sequence (`Adopted{baseline_decreased}`), and a verifier's stored baseline MUST be able to express that decrease. Rationale: a monotone maximum cannot record the adoption of a lower-sequence winner.

**R13 — Domain separators and the identifier's construction.** The key-event signature preimage uses `"SCP-KEL-EVENT-V1:"` under the §9.5.1 construction, and the first field after the separator is the event-type discriminator byte, because a verifier derives the kind before it parses the fields the kind carries. The pre-rotation commitment uses `"SCP-PREROTATION-COMMITMENT-V1:"` as a commitment-hash domain, and the key-event seal uses `"SCP-KEL-SEAL-V1:"`. The **identifier** is `SHA-256("SCP-KEL-ID-V1:" || inception_signed_preimage)`, where `inception_signed_preimage` is the inception event's complete signed preimage with its identifier and predecessor-digest fields set to the all-zero placeholder (definitions); a verifier recomputes it under R2. The identifier separator is distinct from the event separator so that no signature preimage's digest is ever an identifier and no identifier is ever a digest a key signed. All four separators are registered in §9.18.2.

**The routing derivation over an identifier is `routing_id = SHA-256("scp:did:" || identifier_bytes)`** over the identifier's 32 raw digest bytes. A relay checks a frame's `identifier` field against the routing id it was published at under that derivation (§9.10.12), and §3.10.2 cites this sentence rather than restating it. The derivation consumes the digest and never a textual encoding, so it is fixed now and waits on nothing; the identifier's textual form is a display and URL concern, and a later revision of this section fixes it together with the preimage field order. Because the identifier encodes no key, the routing id derives no key either. The root is a key list with a threshold from the first version, so that an organization and a person incept under one schema; the inception preimage's shape is frozen by the identifier construction, and a shape absent at inception cannot be added to an existing identity.

**R14 — The verdict taxonomy.** A resolution returns exactly one of the following, and every rule above cites its variant; every SDK binding carries the six names unchanged. A resolution either delivers a verified key state at or newer than the accepted head, or it does not; `Invalid` and `Contested` reject on their own terms. `Confirmed` — the candidate is the accepted head (R12). `Adopted{head, baseline_decreased}` — the verifier adopted a new head, on the accepted chain or by R6, and the flag says whether the accepted sequence decreased (R12). `Contested{tie: TerminalByKeyMaterial | Pending, heads, shared_prefix_head, fork_position, residue}` — equal rank under R6, with the tie class, the digests of every tied head the verifier retained, the shared prefix's head digest, the fork position (R7), and the count of rank-1 candidates the retention bound left unretained (R9; zero in every case but a rank-1 flood). `Inconclusive{cause: MissingEvents{range, failed_sources} | CopyDefect{at_event} | SingleSource{reached_sources}}` — the resolution delivered no key state the verifier may act on, for the named cause: the events linking a candidate to the accepted chain were not served, a served copy failed verification as a copy-level defect (R3), or a first contact reached fewer than the two relays R11 requires (R11). `Invalid{at_event}` — the chain fails R1–R4 at a named event by an author-attributable defect (R3); this is the only cause, and a copy-level defect never produces this verdict. `Discarded{accepted_head}` — the candidate is a head of the accepted chain at a sequence strictly lower than the accepted head, which the variant names; the verifier changed no stored state (R12). A discard is a verdict so that a consumer routes it, and §9.7.1 routes it as no refresh of the key state: it is not the success branch, because the resolution delivered nothing newer than the baseline the verifier already held. The contested verdict, the retained suffixes it rests on, and the accepted-head baseline MUST survive the verifier's restart and MUST be persisted before any verdict is acted on; a persist failure returns an error and not the verdict.

**Worked examples.** Notation: e0 is the inception event, which installs root R0 and fixes a commitment C over next set P (1-of-1 unless stated); a number is a sequence; the owner is the legitimate controller.

1. **A root thief forks early; the owner's device holding R0 is gone.** The owner's chain is e0 through e9 (R0-signed `KeyState` events). The thief, holding R0, forks at e5 and appends a5 through a50, all R0-signed. The owner no longer holds R0, so it signs a `RootRecovery{Lost}` at e10 that reveals C, installs a fresh root K′, carries a complete key state, and fixes C′. The shared prefix is e0 through e4 and its standing commitment is C. The owner's suffix reveals C, so its rank is 1; the thief's suffix reveals nothing, so its rank is 2. The owner's chain wins under R6 wherever e10 sits, and the thief's head sequence 50 decides nothing. Under R8 the derived key state after e10 is e10's snapshot, so nothing the thief installed survives; under R9 the owner's suffix and the thief's suffix occupy two store slots at that routing id, because they diverge, and a relay serving a slot serves its chain from e0. The thief cannot evict the recovery by appending: eviction is by rank, the owner's suffix is rank 1, and R9 never evicts a rank-1 suffix. **Nor can the thief make the recovery unpublishable by inflating its own chain.** The owner publishes from e0, and the segment carrying e5 attaches by its predecessor digest to e4, which every relay that holds either chain already has; the thief's forty-six events sit in the other slot and stand between nothing. **The same holds where a thief appends to the owner's own chain without forking**, which grows the owner's from-inception chain past one frame: the owner publishes it as several segments in sequence order, each attaching to the head the previous segment left, and the segment carrying the recovery is the last of them (R9's write rule). **The scope of that guarantee is a validating relay.** A verifier receives both chains from every validating relay it queries; a non-validating relay and a foreign transport deliver availability and no eviction resistance, so a verifier querying only those may receive one chain.
2. **A copied pre-rotation key, the thief forks early.** The owner's chain is e0 through e60 with R0 intact and trusted. The thief holds a copy of P, forks at e10 with a `RootRecovery{Lost}` a11, and appends to a50. The owner signs a `CommitmentRollover` at e61 that reveals C and carries R0's signature. Both suffixes reveal C, so both are rank 1 and the identity is contested, terminal by key material (R7). The same verdict follows when the thief also holds R0 and the owner signs a `RootRecovery{CoSigns}` instead (Pin A).
3. **Two root-only suffixes.** The owner's two devices both hold R0. Device A appends a `KeyState` e10a and device B a different `KeyState` e10b. Neither suffix reveals C, so both are rank 2 and the tie is pending (R7). The owner signs a `CommitmentRollover` e11a on device A's suffix; that suffix is now rank 1 against rank 2, and it wins. An owner who has lost P faces a permanent rank-2 tie.
4. **A backup of a spent key later reaches the root thief.** The owner's chain carries a `RootRecovery{Lost}` r20 that reveals C_prev over P_prev and installs K′; the chain continues to e40. The thief, who holds R0 by r20's own premise, later obtains a backup of P_prev and forks at e19 with a `CommitmentRollover` a20 that reveals P_prev and carries R0's signature. Both suffixes reveal C_prev, so both are rank 1 and the identity is contested, at any later date; the thief's R0 co-signature wins it nothing (Pin A). R9's retention past the last reveal is what lets a verifier see this fork at all. Destruction that reaches every backup medium is what prevents the contest from arising.

### 9.7.4.3 Witness and Watcher Layer (Layer B)

**This section is the home of the witness protocol, and it does not yet carry it.** ADR-063, the inception-derived key-event-log identity substrate, settles the model this section will state: witness relays cosign an identity's log head, a watcher holds every later observation to the first head it saw at a given sequence, and a pair of root-signed heads of which neither extends nor supersedes the other proves the identity equivocated. Detection is the mandatory base and never gates resolution; a witness quorum is a relying party's opt-in policy for one decision of its own; non-equivocation holds only against a witness set the watcher recognizes as independent of the identity's controller, and against an unrecognized set the party degrades to the log's own rules rather than reading false assurance. The definitions of §9.7.4.2 already name the witness set, the witnessing interval, and the accountability threshold as key state, and R3 bounds the two cosigning parameters wherever an event carries them, so an identity incepted today already carries the fields this layer reads and adding the layer renames no identifier.

**What this section will state, and what no other section may assume until it does:** the cosigned-head wire format and its signature preimage; **that the cosigned head covers the identity's current service-record digest beside the log head** (the identity-substrate plan §1a homes the service record as a second owner-signed surface inheriting Layer A and Layer B, so the witness cosigns both digests in one signature); the consistency proof a witness verifies before it cosigns; the threshold and interval bounds; the policy by which a relying party accepts a witness set as controller-independent; and the watcher's first-seen comparison, its durable baseline, and the fault proof it emits. **Until this section carries them, every rule in §9.7.4.2 that could read a witness reads none.** A rank-1 tie under R7 is terminal for every party; a first-contact resolver takes the two relays R11 requires and no cosigned head; the ceremony of R10 completes at confirmed publication and destruction, with witness submission outside it; and the non-destructible sole-custody failure of §9.7.4.1 stays unmitigated. Each of those sections cites this one for the absence rather than restating it, and none of them treats the absent layer as a mechanism it may rely on.


## 9.8 Message Security

This section specifies how SCP prevents message forgery, replay attacks, and ordering manipulation.

### 9.8.1 Envelope Integrity (Two Independent Checks)

Every SCP message has two independent integrity verifications, both inside the encrypted payload. Neither is verifiable by relays — relays see only opaque blobs.

**Inner check 1 — Ed25519 identity signature.** The sender signs the payload with their Active Signing Key (`#active`). The signature is over a domain-separated, length-prefixed canonical hash: `SHA256("SCP-INNER-ENVELOPE-V1:" || version || message_type || len(context_id) || context_id || len(sender_did) || sender_did || epoch || generation || sequence || timestamp || len(payload_hash) || payload_hash || len(provenance_hash) || provenance_hash || len(signing_key_id) || signing_key_id)` where `payload_hash` covers the original plaintext (before padding), `provenance_hash` covers serialized provenance metadata, and an absent value is written `00 00 00 20` followed by the 32 bytes `SHA-256(0x00)`, which is what `len(provenance_hash) || provenance_hash` yields under §9.5.1's optional-field rule for a length-prefixed field, and `signing_key_id` is the verification-method fragment the sender signed under, `#active`. Because `signing_key_id` is inside the signed preimage, a tampered or forged verification-method claim invalidates the signature: the verifier resolves the public key for the *declared* `signing_key_id` from the sender's key state, and the signature can only verify if that method's private key actually signed — so a claim naming a method that did not sign fails verification. Including `version` and `message_type` (a discriminator byte) prevents downgrade and type-flipping attacks. Processing order: hash plaintext -> hash provenance -> sign -> pad -> sender-key encrypt -> MLS encrypt. Reverse on receipt: MLS decrypt -> sender-key decrypt -> strip padding -> resolve sender VM key by `signing_key_id` -> verify signature -> verify payload_hash -> verify provenance_hash. A failed signature means the envelope was tampered with or forged and MUST be rejected. **A verifier MUST reject an envelope whose `epoch` field differs from the MLS epoch that decrypted it.** The sender signs the `epoch` field, so a compromised key's holder could otherwise set it to any value; §9.7.1 orders content against a key's compromise boundary by the decryption epoch, and this check is what keeps the signed field from contradicting it.

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

The canonical Merkle event log records the **convergent** (MLS-commit-ordered) events as a single-parent hash chain in append order; for that totally-ordered prefix, two events referencing the same parent indicate a fork — possible equivocation (§9.9). **Application events** (messages, outlet invocations) are NOT part of this chain: in the interim they are excluded local `ContextEvent`s (ADR-011 amendment), and in the end state they are ordered by a **causal DAG** (ADR-051) in which multiple events legitimately reference a shared frontier and are deterministically linearized — concurrent branches are normal, not a fork.

**Interaction with relay ordering:** Relays do not guarantee message ordering. The SDK MUST re-order messages locally using `(epoch, generation, timestamp)` before presenting them to the application layer.

**Authoritative ordering:** The Merkle log order is authoritative, not timestamps. Timestamps are hints for the SDK to reconstruct order in real-time. Once events are committed to the log, the log order is the permanent record. For the convergent commit-ordered prefix this is the single-parent chain above; for DAG-ordered application events (ADR-051) the authoritative order is the deterministic linearization of the causal DAG (ADR-051 §2). The per-sender `(epoch, generation, timestamp)` reconstruction remains a delivery/display hint only. This non-authoritativeness is about *ordering*: timestamps do not determine an event's position in the log. It does not make the leaf `timestamp` a per-member-local or otherwise non-convergent field. The `timestamp` recorded in a committed Merkle leaf is the committer-assigned value — the `created_at` of the signed SCP envelope carrying the commit, copied by every member (§7.3.1, §9.8.2) — convergent across honest members and bounded to real time within the clock-skew tolerance (§9.8.2). It is a convergent, bounded annotation carried *on* the authoritative order, not the orderer.

### 9.8.4 Forgery Prevention

**Message forgery:** Prevented by Ed25519 inner signature + MLS membership_tag. Both checks are inside the encrypted payload (§9.8.1). An attacker who does not hold a member's private key cannot produce a valid inner envelope, and an attacker without MLS epoch secrets cannot produce a valid membership_tag.

**Attestation forgery:** Attestations (§7.4) are signed by their issuer's DID key. Forgery requires the issuer's private key.

**UCAN forgery:** UCAN tokens contain a delegation chain where each delegation is signed. The mandatory `nnc` (nonce) field prevents token reuse outside the intended scope.

**Provenance forgery:** Data provenance records (§7.7) are attached by the SDK and signed as part of the enclosing envelope. An agent cannot fabricate a provenance claim for data sourced from a context it was never in, because provenance records are verifiable against the source context's Merkle root (for persistent-scope sources).

### 9.8.5 Sequence Validation

Each sender in a context maintains a monotonically increasing SCP sequence number (distinct from MLS generation numbers, which are MLS-internal). This sequence number is included in the envelope. For *application messages* it is no longer a Merkle event-log entry: in the interim they are excluded local `ContextEvent`s (ADR-011 amendment), and in the ADR-051 end state the DAG leaf carries causal head-references in place of a committer sequence (§7.3.1; ADR-051). Commit-ordered events retain the committer-assigned sequence in their leaf.

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

**Multi-relay cross-check:** Context messages SHOULD be published to at least 2 relays (recommended: 3). Recipients subscribe to every relay in the sender's relay list, which they read from that identity's service record (§9.6.3), and merge received envelopes. If relay A delivers an envelope and relay B does not, this is an inconsistency. After a timeout (recommended: 30 seconds), the inconsistent relay is marked as potentially adversarial.

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
  signature:    Ed25519Signature // signed by the sender's #active key
}
```

Checkpoints are sent as regular MLS application messages (encrypted, authenticated).

**DAG-leaf extension (ADR-051).** For contexts with DAG-ordered application leaves, the checkpoint additionally carries a canonical `frontierRoot` (a commitment to the member's observed DAG frontier), and the equivocation test compares `merkleRoot` at equal `frontierRoot` rather than equal `eventCount` (a frontier is a *set* of head hashes, not derivable from the scalar count; see ADR-051 §5). The scalar fields above remain authoritative for the totally-ordered commit prefix.

**Checkpoint comparison:** On receiving a checkpoint from another member, each member compares:

- `eventCount`: Must match (within tolerance for in-flight messages). Divergence of more than 5 events indicates inconsistency.
- `merkleRoot`: Must match for the same `eventCount`. Divergence indicates equivocation or log corruption.
- `epoch`: Must match. Divergence indicates a missed MLS Commit (possible suppression).

**Cryptographic equivocation test vs. application-layer heuristics.** The "divergence of more than 5 events" / "within tolerance" language on `eventCount` is an application-layer heuristic for distinguishing benign catch-up lag (a peer that is merely Behind or Ahead because it has not yet observed all in-flight events) from an alarm condition worth surfacing. It is NOT the cryptographic equivocation test. The cryptographic equivocation test is unambiguous and conservative: **equal `eventCount` with different `merkleRoot`**. Two honest members reporting the same event count but different roots cannot be reconciled by any ordering of in-flight messages — one of them was served a forged history. Implementations MUST NOT loosen the equal-count test (e.g., by tolerating root divergence within the 5-event window); the count tolerance applies only to deciding whether a count gap is alarming, never to weakening the equal-count-different-root signal.

**Convergent-log requirement.** The equal-count/equal-root test is sound only if honest members build the *same* log. The canonical event log MUST therefore contain only **convergent** events — those every honest member derives identically from the MLS-commit-ordered stream (governance, membership, lifecycle, role, access, provenance, economic *governance* actions, compromise recovery, app-binding), as enumerated by the canonical `EventType` taxonomy (ADR-011). Attestations are NOT in this list: they are credential-layer artifacts (DID-document entries, relay-published blobs, the trust-protocol cache; §7.4), not context-log leaves — the equal-count/equal-root equivocation test is therefore unaffected by them. Per-recipient or detection signals (`MessageReceived`, `EquivocationDetected`) and routing-bootstrap signals (`PseudonymAnnounced`) are local `ContextEvent`s, never log entries. Per-author application activity (`MessageSent`, `OutletInvoked`, `PaymentReceived`) has no global order on its own and is brought into a convergent canonical order by the causal-DAG ordering of ADR-051; until that lands it is excluded from the canonical log (surfaced as a local `ContextEvent`), so the equal-count/equal-root invariant holds over the convergent subset. For the DAG-ordered application leaves specifically, the equivocation test is taken at **equal frontier** — a causally-stable cut — not equal scalar count: two honest members can have observed different in-flight application events, so equal count need not mean equal leaf set, and the `ConsistencyCheckpoint` therefore commits to the DAG frontier and roots are compared at equal frontier (ADR-051 §5). The totally-ordered commit prefix continues to use position directly. Soundness of the equal-count/equal-root test further requires that *every field* of a canonical leaf be convergent — including the `timestamp`. The leaf `timestamp` is the committer-assigned value (the `created_at` of the signed SCP envelope carrying the commit, copied by every member; §7.3.1, §9.8.2), not each member's local wall-clock reading. Were members to stamp leaves with per-member-local times, two honest members at the same event count would compute different roots with no equivocation present — a false positive that would force the equal-count test to be weakened, the outcome this section forbids. The committer-assigned timestamp keeps leaf bytes byte-identical across honest members while remaining tamper-evident and real-time-bounded within the ±5-minute future bound of §9.8.2. For timer-triggered events that carry no commit envelope (TTL expiry/close, governance-freeze expiry, deferred economic-policy application), the convergent value is the pre-computed deadline already in convergent context state, not local `now()`. This does not make timestamps authoritative over log order (§9.8.3): the order is the orderer; the timestamp is a convergent, bounded annotation carried on it.

**Divergence resolution:** If Merkle roots diverge, members exchange event log proofs to identify the first divergent event. This reveals which relay served which version. The context's governance model handles the response.

**Sybil-amplified equivocation defense:** The Relay Consistency Protocol is NOT a majority vote. ANY divergence between ANY two honest members detects equivocation. An attacker who controls Sybil members and a relay can make the Sybil members confirm the attacker's version, but this is irrelevant — two honest members comparing checkpoints will detect the equivocation regardless of how many Sybils agree with the attacker. The defense requires only two honest members in the context.

**Two-tier equivocation response.** The response to detected equivocation has two distinct tiers, and they are specified — and may be implemented — separately:

- **(a) Local detection alert (detect-and-surface).** On observing two checkpoints with the same `eventCount` but different Merkle roots, an honest member raises a *local, SDK-surfaced* `EquivocationDetected` alert (the runtime/SDK event; see §23.7). This is the minimum conformant equivocation-detection behavior: a conformant member MUST detect the divergence and surface it to the application layer and event log. Tier (a) does NOT require constructing or distributing the signed, proof-bearing `EquivocationAlert` MLS message described below — an implementation of the detection step alone is complete without it.
- **(b) Signed governance alert (the equivocation governance response).** The publication of a signed, proof-bearing, MLS-distributed `EquivocationAlert` (with `proof: Vec<MerkleProof>` inclusion proofs and `conflicting_hashes`) and the `equivocation_policy` enforcement that follows are a *separate, subsequent governance flow*, specified separately. Tier (a) always precedes tier (b): detection is what triggers the governance response.

The numbered steps below specify tier (b), the equivocation governance response. They build on — and are gated by — the tier (a) detection above.

**Equivocation governance response.** When equivocation is detected (divergent Merkle roots at the same event count between two honest members) and tier (a) has surfaced it, the equivocation governance response proceeds as follows:

1. **EquivocationAlert event.** The detector publishes an `EquivocationAlert` as an MLS application message, signed by the detector's Active Signing Key (`#active`):

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
  signature:            Ed25519Signature     // signed by the detector's #active key
}
```

The signature covers `context_id || detector_did || relay_url || local_checkpoint.merkleRoot || divergent_checkpoint.merkleRoot || timestamp` using the canonical signed structure format (§9.5.2). The `proof` field includes Merkle inclusion proofs for the conflicting events from both the detector's and the divergent member's logs, enabling independent verification by any group member.

2. **Alert distribution.** The `EquivocationAlert` is distributed to all context members as a standard MLS application message (encrypted, authenticated). Every member's SDK processes the alert independently.

3. **Governance response.** The context's governance engine processes the `EquivocationAlert`. The response is configurable per context via `equivocation_policy` in context parameters. The `equivocation_policy` parameter and its enforcement (`warn` / `suspend_relay` / `remove_relay`, below) are part of the equivocation governance response (tier (b)), not the local detection step (tier (a)) — a member that has only implemented tier (a) detection neither reads nor enforces `equivocation_policy`. The configurable responses are:

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
- **Resolution layer:** Multi-relay querying + caching bound resolution-based tracking (§9.10.7)
- **Query layer:** Pseudonyms + relay partitioning prevent subscription analysis (§9.10.8)
- **Push layer:** Fully opaque push notifications (§10.7)
- **Blocking layer:** AES-256 sender-side keys enable cryptographic blocking without MLS group changes (§9.16)
- **Cross-context key isolation:** Independent MLS key material per context (§9.10.9)
- **Delivery layer:** Relay-side delivery jitter breaks timing correlation between PUBLISH and delivery (§9.10.10)

The following is listed here because §9.10 is where relay-stored record formats are specified — not because it is a privacy layer:

- **Public-record format (not a metadata-privacy protection):** the key-event record frame (§9.10.12) is the *format* for the unencrypted, self-certifying key-event record — the structural counterpart to the encrypted outer envelope (§9.10.2). It does **not** conceal metadata: a key-event record is a public record that exposes the identifier and its keys in the clear by design, and the identity's service record exposes its relay endpoints on the same terms. It is catalogued alongside the privacy layers above only because it is a relay-stored record format; it addresses no attack surface in the privacy sense.

This section specifies what the protocol protects, how it protects it, and what residual risks remain.

### 9.10.1 What Is Confidential

- Message content (MLS encryption)
- Context-internal state: roles, outlets, governance actions, event log content (all encrypted within the MLS group)
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

Here `identity_key_material` is the 32-byte `pseudonym_secret` (NOT the public key) defined in §9.10.4.A — a value that is not publicly derivable. `Ed25519_keygen(context_seed[0..32])` interprets the 32 bytes as an **RFC-8032 Ed25519 seed**: the keygen applies the standard expansion (SHA-512 of the seed, then clamp the lower 32 bytes to form the scalar) internally. Implementations MUST NOT treat `context_seed` as an already-clamped scalar. This single interpretation is what makes software pseudonyms agree byte-for-byte across platforms (see §25.19 for known-answer vectors).

- **Per-identity, not per-key.** The pseudonym is derived from `identity_key_material` (the `pseudonym_secret` of §9.10.4.A), so one identity sends every message in one context under one pseudonym, whichever operational key signed the individual message. A delegated agent identity holds its own key-event log and its own `pseudonym_secret`, so it derives its own pseudonym in each context it joins (§9.1 invariant 1).
- **Deterministic:** Same identity + same context = same pseudonym.
- **Unlinkable across contexts:** Different context_id = different pseudonym. Relays cannot correlate activity across contexts.
- **Verification:** Sender includes full DID inside MLS-encrypted payload. Group members verify pseudonym-to-DID mapping on first encounter and cache the association.
- **No ZK proofs** — unnecessary complexity since only group members need to verify the mapping.
- The SDK handles derivation, caching, and verification transparently.
- **Custody compatibility.** Pseudonym derivation is performed via `KeyCustody::derive_pseudonym(identity_key_handle, context_id)` (ADR-006). The HMAC-SHA256 computation happens inside the custody boundary — the private key never leaves it. For software keys, the HMAC key is the `pseudonym_secret` derived deterministically from the private seed via HKDF (see §9.10.4.A). For hardware-backed keys (Secure Enclave, Android Keystore TEE, HSM), the `pseudonym_secret` is a device-local value held inside the hardware boundary. **Output equivalence is therefore custody-dependent:** software custody produces identical output for the same identity seed and `context_id` across all platforms (cross-platform deterministic); hardware custody produces a device-local pseudonym that is intentionally not identical across devices, because the underlying key is non-exportable by design (see §9.10.4.A). See §9.10.4.A for the authoritative pseudonym derivation specification (ADR-002 criterion 1 as a secondary cross-reference).
- **Bootstrap channel for pseudonym announcements; no shared-RID fallback for application data.** A member who has just joined or imported a context — or restored one from a snapshot that carried no peer registry — does not yet know any peer pseudonyms; their pseudonym registry is empty. (A warm restore carries the persisted peer registry forward, so it is not in this bootstrap state.) To close this bootstrap gap, pseudonym announcement messages — and ONLY pseudonym announcement messages — are sent to the shared `context_routing_id` EXCLUSIVELY. They are NOT also fanned out to known peer pseudonyms. Every group member already subscribes to the shared routing ID (for MLS management traffic), so a single publish to the shared RID reaches every current subscriber regardless of whether the sender has learned their pseudonym yet. Application messages (all non-announcement payloads) use STRICT pseudonym-only fan-out — they are NEVER sent to the shared routing ID. This is a hard requirement, not a best effort: the shared `context_routing_id` is derivable by any relay from the public context id, so addressing the identical MLS ciphertext to both the shared RID and a peer pseudonym RID would let a relay positively correlate that pseudonym to the context by matching the blobs. There is therefore no "fall back to the shared routing ID when a peer pseudonym is unknown" path for application data — an application send into a multi-member encrypted context with an empty pseudonym registry fails closed (peers must first announce) rather than silently leaking onto the shared channel. A single-member encrypted context (the sender is the only member) addresses zero recipients: the application send is a no-op — no ciphertext is emitted, no economic charge is applied, no message event is recorded, and the sequence reservation is rolled back — because there is no peer to fan out to. The importer of a context MUST itself be a member of the imported snapshot; importing as a non-member is rejected, since the derived pseudonym would address a routing ID no peer expects, leaving the member silently unaddressable. The announced pseudonym VALUE is validated at ingest: a member may not announce the zero sentinel, the shared `context_routing_id`, or the broadcast `SHA-256(context_id)` RID for their own DID, and may not claim a routing ID already registered to a different DID; such announcements are rejected and the registry is left unchanged. Privacy tradeoff: an active relay can observe that announcement traffic flows over the shared RID, but the relay can already observe MLS membership and subscription patterns there; the sensitive payload remains inside pseudonym-only traffic.

**Withheld announcements are self-affecting.** A member learns peers' routing pseudonyms only from the announcements those peers broadcast, so a member that never announces its own pseudonym makes *itself* unaddressable — peers cannot derive its routing pseudonym and therefore cannot fan application messages out to it. In a context of three or more members this harms only the withholder: its absence from any one peer's registry never empties that registry, so the honest members still address one another normally, and the withholder can still send to any peer whose announcement it has already received. The sole boundary case is a two-member context — if the only peer withholds, the honest sender's registry stays empty and its application sends fail closed (`PseudonymRegistryEmpty`, above) for want of any other peer to address. That is the intended consequence of having no shared-RID fallback (a withholder is never silently routed onto the shared channel), not a fan-out defect: the denial is confined to that single pair and is self-inflicted by its only counterparty. Announcement is automatic on join and on import and rides the shared `context_routing_id` channel described above, so a persistent, deliberate withholder is running a non-compliant SDK — which the trust model validates announced values against but cannot otherwise constrain (§7.1, §9.4); a transient announcement failure (e.g. relay unavailability) drops a compliant member into the same self-affecting state until it re-announces. No first-announcement grace period, retry, or pull mechanism is therefore specified: a compliant member's announcement propagates on its own, and the empty-registry fail-closed clears as announcements arrive.

**Residual metadata exposure (passive-reader unlinkability, NOT blob-matching unlinkability).** Per-context pseudonyms give application data **pseudonym-address unlinkability against a passive metadata reader**: a relay that only reads routing IDs cannot tell which pseudonym addresses belong to the same context, nor correlate a pseudonym to a DID. They do NOT provide full unlinkability against a relay that matches blob *contents*. Two residuals remain after the pseudonym re-home closes app-data sender-correlation, and are stated here honestly rather than over-claimed:

1. **Shared-RID management-traffic beacon.** The shared `context_routing_id` is still the address for MLS *management* traffic — sender-key distribution, recovery, and epoch / governance commits — and every member subscribes to it. A relay observing the shared RID therefore learns that the context exists, that it is active, and the timing of its membership churn and governance activity. This is group-wide *control* metadata (existence, liveness, churn/governance timing), not per-author application content, and is lower-sensitivity than the per-author send-pattern correlation that pseudonym-only application fan-out eliminates. It is an inherent cost of using a shared management channel; eliminating it requires per-recipient management delivery, which is out of scope for this scheme.
2. **Identical-ciphertext blob-matching.** Application fan-out seals the payload ONCE and sends the **identical** MLS ciphertext blob to all N recipient pseudonym addresses. A relay that matches identical blobs across addresses can therefore group those N pseudonyms as belonging to the same message — and, across many messages, as belonging to the same context — without ever reading a routing ID it could not already derive. Pseudonym addressing defeats the passive *address* reader, not the *blob* matcher. Full unlinkability against a blob-matching relay requires per-recipient re-encryption (an O(N) seal that produces a distinct ciphertext per recipient), which is deferred to the relay-blinding work and is NOT provided here.

Net: this scheme provides **pseudonym-address unlinkability against a passive metadata reader**, NOT full unlinkability against a relay that correlates blob contents or watches the shared management channel. The shared-RID beacon and identical-ciphertext residuals are accepted, documented limitations, not defects.

**Browser-transport residuals (ADR-057 in-browser client, as-built 2026-07-17).** The in-browser client's relay transport carries additional honest residuals beyond the two above. They are real relay correlators — stated plainly, not softened:

1. **Subscriber-cardinality correlator.** A per-member pseudonym routing id has exactly **one** subscriber; the shared `context_routing_id` has **N** (every member subscribes to it). A relay that clusters connections by shared-RID subscriber cardinality can — from routing IDs and subscription patterns **alone**, without matching any blob — reconstruct a context's full pseudonym set and bind each pseudonym to a connection/IP. This is **NOT closed** by the per-recipient re-encryption / relay-blinding fix named for the identical-ciphertext blob-matching residual above: that fix addresses payload *matching*, whereas this correlator reads the *subscription-graph structure* (which RIDs a connection subscribes to, and how many subscribers each RID has). It is a distinct, currently-open residual.

2. **Cross-context connection linkage.** A browser client that multiplexes **all** of its contexts over **one** relay connection is linkable across those contexts *by that connection* — the relay attributes every context riding the connection to a single client/IP. This **contradicts the "Unlinkable across contexts" property** claimed for per-context pseudonyms above: pseudonyms unlink the *routing IDs*, but a shared connection re-links the *contexts* at the transport layer. Stated honestly: per-context pseudonyms do not, on their own, deliver cross-context unlinkability against a relay that observes one client's multiplexed connection.

3. **No relay partitioning or cover traffic in the browser transport.** The as-built browser transport ships **without** relay-set partitioning and **without** cover traffic. The mitigations §9.10.4.1 leans on for non-rotating contexts — "cover traffic, padding, relay partitioning" (also §9.10.6, §9.10.8) — therefore **do not apply to** the browser transport, so neither the subscriber-cardinality correlator nor the cross-context linkage above is blunted by them. A single browser client on a single relay connection, with no partitioning and no cover traffic, is the worst case for both.

4. **Reciprocal-announce is an ACTIVE per-join publish signal.** The announce mesh (ADR-057) is not passive: each join triggers a **burst of `O(N)` publishes to the shared `context_routing_id`** — the joiner announces once, and every one of the N existing members reciprocally re-announces on learning the new peer. A relay watching the shared RID therefore reads, from the **publish pattern alone** (without matching any blob), that a join just occurred, roughly **how many members (N)** the context has (the reciprocal-burst size), and the **timing** of each membership change. This is distinct from residuals 1–2, which are **passive subscription-graph** correlators (who subscribes to what): this one is an **active traffic-shape** signal emitted by the announce protocol itself. It is inherent to a live, backfill-free reciprocal mesh over a shared channel; blunting it needs the cover-traffic/padding this slice does not ship (residual 3) or a per-recipient announce delivery that does not ride the shared RID.

These are residuals of the **as-built** browser transport, disclosed for threat-model honesty. They are real relay correlators the pseudonym scheme does not claim to close — not defects, and not softened by the address-layer unlinkability the scheme does provide.

#### 9.10.4.A Pseudonym Derivation Privacy Model

**Threat: publicly derivable pseudonyms enable membership enumeration.** If `identity_key_material` in the HMAC were the raw Ed25519 public key bytes (which are public by definition), any party knowing a `context_id` and a DID's public key could compute `HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")` and test whether the resulting pseudonym appears as an active subscription on a relay. This constitutes a membership enumeration oracle.

**Mitigation: pseudonym secret.** The `identity_key_material` used in pseudonym derivation MUST be a 32-byte symmetric secret that is NOT publicly derivable. The pseudonym secret is generated alongside the identity keypair and stored within the custody boundary:

```
pseudonym_secret = HKDF-SHA256(
  ikm  = ed25519_private_seed,  // the 32-byte RFC-8032 seed
  salt = "scp-pseudonym-secret-v1",
  info = "",
  len  = 32
)
```

For **software custody**, the pseudonym secret is derived from the Ed25519 private key bytes during key generation and cached in the `KeyCustody` store. The private key bytes are the only input — the public key is never used.

For **hardware custody** (Secure Enclave, Android Keystore TEE, HSM), where private key bytes cannot be exported, the `pseudonym_secret` is a **device-local** value computed inside the hardware boundary. It is derived from the non-exportable identity key in a way the hardware can reproduce deterministically on that device — for example `SHA-256(TEE_sign("scp-pseudonym-secret-v1"))` (Android Keystore), or an associated 32-byte symmetric key generated during `generate_keypair` and stored within the secure boundary (HSM). The hardware computes the HMAC internally using this device-local secret.

**Stance — software is cross-platform deterministic; hardware is device-local by design:** Software custody derives the `pseudonym_secret` deterministically from the private seed, so the same identity seed and `context_id` produce identical pseudonyms on every platform (Rust, Swift, Kotlin, TypeScript). This is a designed property and is pinned by known-answer vectors (§25.19). Hardware custody is **device-local by design**: the identity key never leaves the device, so its `pseudonym_secret` — and therefore its per-context pseudonyms — are bound to that device and are intentionally NOT identical across devices. Cross-device pseudonym identity is not a requirement of the protocol; a participant who moves to a new device uses the social/device recovery protocol (§3.3), which provisions a fresh identity (and thus a fresh device-local `pseudonym_secret`) at the destination. This is not a limitation worked around — it is the direct consequence of hardware keys being non-exportable, which is the security property hardware custody exists to provide.

**Interim — the ADR-057 in-browser client keys its pseudonym on the per-context MLS key, not the identity key:** The in-browser participant client (ADR-057, "A1 as-built" amendment) runs this SAME derivation *algorithm* (same domain separators, HKDF/HMAC recipe, and RFC-8032 seed interpretation — byte-identical to native, pinned by the §25.19 cross-target KAT), but keys it on the **per-context MLS `SignatureKeyPair`** the browser holds in wasm rather than the DID **identity** key — because in that slice the identity key is not reachable inside wasm (only the MLS key is). Consequently the browser's per-context pseudonym does **not** byte-match a native member's identity-keyed pseudonym for the same human/context. This is a **device-local pseudonym** in exactly the sense above: each member **announces its own** per-context routing id and peers **record** it from the authenticated announcement (§9.10.4 pseudonym announcements), so no member ever *recomputes* a peer's pseudonym and cross-device byte-parity is **not a routing requirement**. It is a knowing, human-ruled interim deviation from this section's identity-key source, and it resolves with #1980 (when the identity key becomes reachable by the browser, the derivation moves onto it, restoring the identity-key source and native↔browser byte-parity for the same human). See ADR-057 "Amendment (2026-07-16 — Option A)", the A1 as-built note.

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
- **In contexts with discovery outlets:** Public or discoverable contexts publish their `context_metadata_key` in their context entry. This preserves the "legibility before opt-in" property for contexts that want to be found, while keeping non-discoverable contexts invisible to probing.
- **Rotation:** The `context_metadata_key` MAY be rotated via a governance action. On rotation, the context re-publishes metadata under the new routing ID and maintains the old routing ID for a grace period (2x blob TTL).

**Derivation rule:** Contexts use the keyed `HMAC-SHA256(context_metadata_key, context_id || "scp-metadata-v2")` derivation. The unkeyed `SHA-256(context_id || "scp-metadata")` form is NOT used — it is publicly derivable and would reintroduce the enumeration oracle described above.

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
- **Rotation is opt-in:** Contexts that do not opt into rotation use v1 derivation with static pseudonyms. The existing mitigations (cover traffic, padding, relay partitioning) provide substantial protection for these contexts. This is a per-context configuration choice, not a compatibility shim.
- **Custody compatibility:** Same as v1 — `KeyCustody::derive_rotatable_pseudonym(identity_key_handle, context_id, pseudonym_epoch)` delegates the HMAC to the custody boundary, so software custody is cross-platform deterministic and hardware custody is device-local (§9.10.4.A).

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

1. **Every resolution goes to a relay, and the relay operator is the observer.** A relay learns that a resolver IP queried a specific `routing_id`, and it can infer which identity that names when it already stores that identity's chain (§3.10.9). A relay that carries the resolver's own message traffic already sees that resolver's metadata (§9.9.1), so resolution over it discloses nothing new about the resolver.
2. **A first contact spreads its two queries across two relays.** R11's two-relay rule (§9.7.4.2) sends the two queries to a relay the identity lists and a relay in the fallback set, so neither operator sees the whole of a first contact and no single operator is the exclusive observer of any resolution.
3. **Aggressive caching:** 24-hour refresh for active contacts, 7-day for inactive. A resolver detects a stale chain by comparing the served head's sequence against the accepted head (§9.7.4.2 R12). Key change alerts trigger immediate re-resolution.
4. **No batch/prefetch, no resolution proxy.** Caching plus the spread across relays gives practical privacy without new infrastructure.
5. **Residual: a relay in the fallback set sees first contacts it serves no traffic for.** A community relay that stores no chain of its own still learns which `routing_id` a resolver IP asked for. A resolver that requires IP anonymity uses a VPN or Tor at the transport layer, the same control §9.10.11 names for message traffic.

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
- **Relay trust:** Relays see blob sizes (bucketed), TTLs, and pseudonyms. A relay colluding with a context member could correlate pseudonyms to identities for that context only.

### 9.10.12 Relay Key-Event Record Frame

The **key-event record frame** is the unencrypted counterpart to the §9.10.2 Minimal Outer Envelope: where the outer envelope is *confidential by encryption*, a key-event record is *self-certifying through the key-event log it carries* (§9.6.1). It carries an identity's key-event log (§3.10.2) as a public relay record. The frame is named for what it carries: a segment of the key-event log, never a DID document, which ADR-063 defers and this protocol does not produce. It is specified here in §9.10 because §9.10 is where relay-stored record formats live: the outer envelope (§9.10.2) is the encrypted format, and this is the public-record format. This design is issue #482. (See also §9.18.11 Transport and Relay, which fixes the shared relay blob-size and blob-TTL bounds this frame reuses.)

The frame is **minimal and identity-specific — there is no magic tag and no record-kind byte.** Key-event records live at their own `routing_id` domain (`SHA-256("scp:did:" || identifier_bytes)`, §9.7.4.2 R13), so the address is the type discriminant; a frame needs no self-describing tag to say what it is. (A future MLS KeyPackage relay record, if built — issue #2202 — would define its OWN minimal frame at its OWN `routing_id` domain; key-event records and KeyPackages do NOT share a tagged multi-kind envelope family, and this frame introduces no such taxonomy.)

**Storage model — a raw relay blob.** A key-event record is stored as a **raw relay blob** at its routing ID. It is **NOT** wrapped in an `OuterEnvelope`, and its bytes are **NOT** MLS-encrypted — it is a public, self-certifying record whose authenticity comes from the key-event log its `value` carries (§9.6.1), and not from encryption. Publication and resolution use the existing PUBLISH/QUERY operations (ADR-004) verbatim — no new wire types. `ClientMessage::Publish { routing_id, blob_ttl, blob }` writes the frame bytes at the identity's routing ID, and `RelayMessage::Blob { …, blob }` returns them.

**Relay-side validation has one home, and it is `03-identity.md` §3.10.2.** That section states the four checks a validating SCP-native relay runs on PUBLISH, in cheapest-first order, and the four slot-exclusivity rules (a) through (d) that govern a routing id once a frame establishes a slot there. This section states the frame's bytes and restates none of those rules; `09-security-model.md` §9.7.4.2 R9 states the slot key, what a slot holds, the write rule over the assembled chain, and the eviction rule, and §3.10.2 applies R9 without restating it either. Three findings of one review round came from two copies of the validation procedure drifting apart, which is why exactly one section carries it.

Relay-side validation is an **OPTIONAL capability**: the protocol MUST NOT require a validating relay. Foreign transports and adapters that cannot validate store the frame opaquely; resolution stays correct via client-side verification and multi-relay publishing. Validation is an **availability and anti-suppression measure, never a trust dependency** — the resolver re-verifies every record independently by the log (§9.6.1), so a relay that skips, botches, or lies about validation degrades availability only, never integrity.

**Why raw binary, not MessagePack/CBOR.** The frame uses a raw, fixed-layout binary encoding under the §9.5.1 length-prefix discipline rather than a self-describing codec (MessagePack, CBOR). Self-describing codecs admit multiple valid encodings of the same logical value (map-key ordering, integer width, string-vs-binary tags), which would (a) break byte-identical cross-binding decoding — two SDKs could emit different bytes for the same record — and (b) perturb the exact `value` bytes handed to signature verification, since the signed payload must be reproduced octet-for-octet. The frame therefore fixes exactly one canonical encoding.

**Frame layout:**

```
KEY-EVENT-RECORD (KeyEventRecordV2) :=
  version:          u8         = 2           # frame version
  identifier:       [u8; 32]                 # the identity's inception-derived identifier (§9.7.4.2 R13)
  value:            [u8]                     # trailing remainder = one contiguous segment of the identity's key-event log (§9.6.1, §9.7.4.2 R9)
```

- **version** — a `u8`, currently 2. Any change to field encoding bumps the version. **This frame starts at 2 because `0x01` is a live wire version for a different grammar**: the superseded BEP44 DID-record frame, `version ‖ public_key ‖ seq ‖ signature ‖ value` over a 105-byte fixed prefix, which the `scp-protocol` crate still implements and which the key-event record replaces. A decoder that meets `0x01` today has a working grammar for it, so this layout takes 2 and leaves `0x01` to the one frame that still answers to it. This is not migration compatibility, which this pre-release protocol does not carry: the superseded frame is deleted when the key-event record lands in the crates, and `0x01` is then retired rather than reused. There is no magic tag and no `kind` field (the routing-ID domain is the type discriminant, above).
- **identifier** — the identity's 32-byte inception-derived identifier. The relay's step 2 compares the registered routing derivation over this field against the `routing_id` the frame is published at. The identifier encodes no key (§9.7.4.2 R13), so nothing about the frame's authorization follows from it alone.
- **The frame carries no signature.** A signature over the frame would be checked against a key read out of the writer's own chain, and no frame that passes chain verification could fail it except by a byte change that chain verification already rejects, so the frame carries none and the relay's write decision is chain verification plus the slot rule (`03-identity.md` §3.10.2, §9.7.4.2 R9). **The frame carries no sequence number** either. An event's sequence is its position on the chain (§9.7.4.2 definitions), so a chain that extends a stored chain has a strictly higher head sequence by construction and the relay's write rule reads the extension rather than a number beside it; a frame-level sequence would restate the chain's own order in a field a writer supplies.
- **value** — the sole variable-length field, carried as the **trailing remainder** of the frame (no `value_len` prefix). Because every preceding field is fixed-width, `value` is unambiguously `frame_bytes[33..]`; a length prefix would be redundant with the blob's own length and a determinism footgun (two disagreeing lengths). `value` MUST be non-empty and its length MUST NOT exceed `Max blob size` (262144, §9.18.11) `− 33`. It carries one contiguous chain segment, naming the segment's first and last sequence and the events between them in order; a relay serves a slot's chain as the ordered sequence of frames covering inception through head (§9.7.4.2 R9).

The fixed prefix is `1 + 32 = 33` bytes, and the total frame length is `33 + len(value)`. **The frame carries no public key and no root-set digest**: a relay reads the chain's standing root set out of the chain it verified (`03-identity.md` §3.10.2 step 3), so a key supplied by the writer would authorize the writer against itself, and a digest supplied by the writer would let a keyless party replay a genuine frame under many spellings of the same chain and claim a slot for each.

**Every byte of the framing is unsigned, and the chain inside it carries the whole authority.** The frame's `version`, its `identifier` field, and its field boundaries are transport framing that no key signs. **A decoder MUST NOT derive any security-relevant conclusion from an unsigned field, and a relay MUST cross-check the one unsigned field a decision reads — `identifier` — against the verified chain before any decision reads it**: chain verification recomputes the identifier from the chain's inception event and rejects a frame whose `identifier` field differs (`03-identity.md` §3.10.2 step 3). Every other input a decision reads, the standing root set included, the relay takes from the verified chain and never from the framing. After decoding a frame, the resolver authenticates the record by the key-event log the `value` carries — recompute the identifier from the inception event and verify every event under §9.7.4.2 R2 and R3 (§9.6.1); a frame whose chain fails that verification is discarded exactly as a frame that fails to decode is (§3.10.4). Record substitution fails because a chain served under an identifier recomputes to that identifier only if its inception event is the one that identifier names.

**Decoder determinism (normative).** Because the frame is decoded by hand-rolled, byte-identical decoders across every binding, a conformant decoder MUST enforce the following. Any frame that fails any rule is discarded exactly as a chain that fails verification is (§3.10.4) — never trusted, never partially parsed:

1. **Read and check `version` before any subsequent byte.** The `version` field gates the *entire* grammar. A decoder MUST read and validate `version` before interpreting any subsequent byte, and MUST reject (discard, no partial parse) any `version` it does not implement.
2. **Require the fixed prefix in full.** A decoder MUST reject any frame shorter than the 33-byte fixed prefix (`version + identifier`) — truncation is never a partially-valid frame.
3. **Bound-check the `value` length only after the prefix check.** `value` is the trailing remainder, `len(value) = total_frame_len − 33`. A decoder MUST NOT compute `total_frame_len − 33` before rule 2 has confirmed `total_frame_len >= 33`: computing it first can underflow, which diverges between a debug-build panic and a release-build wrap across bindings. With rule 2 satisfied the subtraction cannot underflow. A decoder MUST reject an empty `value` (`total_frame_len == 33`) and MUST reject `len(value) > Max blob size (262144, §9.18.11) − 33`. No widening is required: `len(value)` is an actual buffer length (a valid `usize`, already bounded by the transport's Max blob size) and the bound is a compile-time constant — there is no wire-supplied length field to overflow (unlike a length-prefixed layout).
4. **Decode-and-verify at exactly one site.** Decoding a frame and verifying the chain its `value` carries happen at exactly **one** site (mirroring SCPM's single decode-and-verify site, §9.16.1). No other layer may test, branch on, or depend on the framing bytes.

**Publish / query contract.**

- **Publish** = wrap `(identifier, value)` in a key-event record frame and PUBLISH the frame bytes at the identity's routing ID via the existing PUBLISH operation (§3.10.5), one frame per contiguous segment and the segments in order (§3.10.5 step 3). The relay blob MUST be the key-event record frame — not the bare key-event log bytes, and not an `OuterEnvelope`.
- **Query** = the existing QUERY operation (§3.10.4) with `limit: N` (N = 16) returns blobs stored at the routing ID; the resolver decodes each at the **single** decode-and-verify site, verifies the chain each `value` carries under §9.7.4.2 R2 and R3, and settles two chains that diverge by the fork-precedence rule (§9.7.4.2 R6). It reads no key from the frame. **A slot is an ordered sequence of frames (§9.7.4.2 R9), so a resolver pages a slot by sequence range** and one QUERY does not necessarily return a whole chain: the resolver reads the frames it received, finds the highest contiguous sequence they cover, and issues further QUERYs until it holds inception through head or the relay serves no more. `N` bounds one page and bounds no slot; a chain at the `MAX_KEY_EVENTS_PER_CHAIN` ceiling spans far more frames than `N` (§9.18.17 states the arithmetic). Against non-validating or foreign storage `limit: N` also lets the resolver retrieve up to N candidates and sift them by R2, R3, and R6 (§3.10.4 step 5). See §3.10.2 for why `limit: N` dominates `limit: 1`.
- **Distinct from the outer envelope.** An identity's routing ID carries key-event record frames, not `OuterEnvelope`s; a resolver MUST NOT deserialize one as the other. The two are disjoint at two independent levels: **(a) routing-ID space** — key-event records occupy `SHA-256("scp:did:" || identifier_bytes)` (§9.7.4.2 R13), disjoint from context routing IDs; **(b) byte level** — a key-event record frame begins with `version = 0x02`, whereas an `OuterEnvelope` is MessagePack-serialized as a map (`rmp_serde::to_vec_named`) whose first byte is always a map marker (fixmap `0x80`–`0x8f`, or `0xde`/`0xdf` for larger maps) — never `0x02`, and never any low byte a frame version will take. A key-event record frame therefore can never be mistaken, byte-for-byte, for an `OuterEnvelope`, or vice versa — a defense-in-depth backstop beneath the routing-ID separation.

**Divergence is defined over events, never over framing.** `03-identity.md` §3.10.4's rule that two records serving heads of one chain at one sequence MUST be byte-identical compares **the chain bytes** the two `value` fields carry, and the sequence it compares is the chain's own, read out of the verified `value` and never a field of the frame. Two records whose chains are identical are one chain however the frames differ, and two chains diverge only where they carry different events at one position (§9.7.4.2 definitions).

**TTL.** Key-event records reuse the shared relay `blob_ttl` (§9.10.2), bounded by `Max blob TTL` = 604800s / 7d (§9.18.11). There is no record-specific TTL and no change to `Max blob TTL`. TTL governs storage lifetime; the chain's own order governs supersession (§3.10.7), and a validating relay's slot rule enforces it on write (§3.10.2). Record permanence is achieved by republication on the 6-day cycle (§3.10.2), not by TTL.

## 9.11 Key Continuity Verification

Equivalent to Signal's "safety numbers." Allows two parties to verify they have the correct keys for each other, detecting MITM on DID resolution.

**Fingerprint format — one construction, and every identifier is inception-derived.** The fingerprint takes the parties' **32-byte identifiers** (§9.7.4.2 R13), never their DID strings. The identifier is already a fixed-length 32-byte digest, so under §9.5.1 it carries no length prefix and the construction waits on nothing.

```
fingerprint = SHA256("SCP-KEY-CONTINUITY-V1:" || id_a || count(a_root_set) || a_root_set_members || a_active_key
                                             || id_b || count(b_root_set) || b_root_set_members || b_active_key)
```

Where `id_a, id_b` are the two 32-byte identifiers ordered by unsigned byte comparison, and the block for the lower identifier comes first; `count()` is a 4-byte big-endian member count (§9.5.1's repeated-field rule); `a_root_set_members` is every member of that root set as a raw 32-byte key, **in the list order the key state carries**, because the root set is an ordered list and its order is signed; and every key is a raw 32-byte Ed25519 public key. **This is the only form, and it covers a root set of any size, the one-member set included**: a personal identity contributes `count = 1` and its single member. An SDK MUST NOT omit the count for a one-member set. A second, count-free encoding for the 1-of-1 case would make two SDKs that each chose a different encoding compute two different values for one pair and raise a maximum-severity MITM alert on an honest pair. Every root member and the operational key are included, so substitution of any single key changes the fingerprint.

**Every key state a verifier accepts names exactly one `#active` key.** Two R3 bullets give the fingerprint a defined value: R3 rejects a state-carrying event whose service-key designation names a key that same snapshot does not list `current`, so at least one key is `current` in the role, and R3 rejects a state-carrying event listing more than one key `current` in any single operational role, so at most one is. `#active` is the identity's one operational role (§9.7.4.2 definitions). This paragraph asserts neither bound on its own account; it cites the two bullets that enforce them. No sentinel stands in for an absent operational key. The `"SCP-KEY-CONTINUITY-V1:"` domain separator prevents cross-protocol signature confusion.

Displayed as:
- A 12-word mnemonic (BIP-39 word list, first 128 bits of the hash)
- A 60-digit decimal number (first 200 bits)
- A QR code encoding the full 256-bit hash

**Verification flow:**

1. Alice and Bob each compute the fingerprint over the two identifiers, the two root sets, and the two operational keys, taking the other party's values from the key state each derived from the chain it adopted.
2. They compare fingerprints via an out-of-band channel (in person, voice call, trusted messaging app).
3. If fingerprints match, key continuity is verified. The SDK records this verification event in identity private state (§3.7).
4. If fingerprints do not match, a party is intercepting resolution or the identity has been taken over. The SDK MUST alert with maximum severity.

**Key change detection.** The identifier does not change when its root changes, so no rename tells a relying party that the person behind an identifier may have changed; and fork precedence (§9.7.4.2 R6) adopts a chain, it does not authenticate a person. This rule is therefore the gate that a rename used to supply.

- **The standing is keyed to the identifier alone.** The SDK keeps, for every identifier it has encountered, one **`ContinuityStanding`**: `Verified`, or `PendingReverify`. Beside it the SDK records the **root-install digest** — the digest of the event that installed the root standing at the moment of the record — as a field of the record, not as part of its key. On first encounter, meaning the first time the SDK resolves that identifier at all, the standing is `Verified` by trust-on-first-use over the chain as it resolved, and the SDK records the root-install digest of that chain. **Trust-on-first-use applies only to a resolution that adopted a chain.** A first encounter whose resolution returns `Contested` sets the standing `PendingReverify` and records no root-install digest, because R7 leaves no adopted chain to trust and the tied heads may install different roots, so there is no digest to record. A `RootRecovery` already in the chain at first encounter is part of the history being trusted on first use; the SDK is not observing one, and it does not fire the rule below. Keying the record to a pair that includes the digest would make every root change look like a first encounter, which is the takeover this rule exists to catch.
- **A `RootRecovery` the SDK observes after the first encounter — whether the verifier `Adopted` it or the identity is `Contested` — IS a key change under this rule and is never a legitimate-change exemption.** The observable trigger is the recorded root-install digest no longer matching the one the resolved chain carries. On observing that change the SDK MUST set the standing to `PendingReverify`, update the recorded digest, invalidate every recorded continuity verification for that identifier, and alert the user at maximum severity that the identity's root has changed. An uncontested `RootRecovery` is exactly the attacker's outcome when the pre-rotation key was exclusively taken (§9.7.4.1's failure-mode table), so a verdict of `Adopted` exempts nothing.
- **An unauthored `KeyState` on the local identity's OWN chain is the device-compromise signal, and it is read on that device alone.** A `KeyState` the local SDK did not author, appearing on the chain of the identity that SDK controls, is R10's self-observation alert: the SDK records it and alerts the human at maximum severity, because a thief holding the root produces exactly such an event. **A peer sets nothing on it.** From a peer's position every `KeyState` of every other identity is unauthored, so a rule that made an unauthored `KeyState` a peer-side key change would set `PendingReverify` at every peer on every routine custody migration of every identity — and `03-identity.md` §3.2.1 calls such a migration transparent. The two events at which a peer sets `PendingReverify` are the two below: an adopted `RootRecovery`, and a `Contested` verdict.
- **A `Contested` verdict for an identifier sets the standing to `PendingReverify`**, whatever kinds the tied events are, so a tie between two `CommitmentRollover` events fires this rule exactly as a `RootRecovery` does. The standing is held against the identifier while the contest stands. **It returns to `Verified` with no human step in one case and no other: R6 resolved the divergence.** When R6 ranks one suffix above the other and the verifier retires the rank-2 equivocation record under §9.7.4.2 R7, it clears the `PendingReverify` that the `Contested` verdict alone set and restores a defined standing. **Which standing:** the standing the identifier held before the contest, where it held one; and where the contest was the identifier's first encounter and it held none, the standing trust-on-first-use would have set for the chain the resolution then adopts (§9.6.4), recording that chain's root-install digest at the same moment. A verifier that restored "the standing before the contest" for a first encounter would restore nothing and leave the identifier with no standing and no root-install digest, so its key-change trigger could never fire. **An escalation clears nothing.** Where the rank-2 record is retired because the divergence escalated to a rank-1 tie, the verifier retires that record and the standing stays `PendingReverify` under the new `Contested` verdict, which is terminal by key material (§9.7.4.2 R7). A rank-2 divergence escalating to rank 1 is the takeover completing, so a rule that cleared on any retirement of the rank-2 record would restore `Verified` at exactly the moment the attacker revealed the standing commitment. The two-device race of §9.7.4.2's third worked example therefore unblocks itself. A resolved tie whose R6 winner installed a new root is not benign: the winner carries a `RootRecovery`, which sets `PendingReverify` on the bullet above and needs the re-verification that bullet requires.
- **The admission and grant gate reads the standing of identifiers other than the local identity.** A device that observes an unauthored change on its own identity's chain records it and alerts under the bullet above; it does not set a standing against its own identifier, because the gate would then lock the controller's own second device out of every context after the controller migrated custody on the first — and the only exit stated below is a fingerprint comparison, which one person cannot perform against themselves. A `RootRecovery` the local SDK signed likewise leaves the local identity's standing untouched on every device that identity controls.
- **One gate reads the standing, and it gates admission and grants — never an existing member's traffic.** While an identifier's standing is `PendingReverify`, the SDK MUST NOT: Add a new leaf for that identifier to a context; **issue a UCAN to it, or accept a UCAN it issued, or accept a UCAN with that identifier anywhere on its delegation chain**; distribute a sender key to a new leaf of it; or auto-accept it at the standing-pair consent gate, the known-identity allowlist, or a cached `author_keys` entry. The gate also governs **inbound** acceptance: no invitation, standing-pair request, or contact-graph promotion from a `PendingReverify` identifier is auto-accepted, and the SDK surfaces its content as unverified, never as the known contact. The SDK surfaces the standing and the reason for it wherever it withholds one of those acts. **This list is the authoritative set of withheld acts**, and every other section cites it rather than enumerating a subset.
- **Both arms of the UCAN clause are load-bearing.** Refusing a UCAN issued *to* a flagged identifier withholds a grant the local SDK would make; refusing one issued *by* it withholds authority the attacker minted. A recovering controller cannot enumerate the tokens an attacker issued under a stolen key, so refusal on the relying party's side is the only act that stops them, and §9.12 says exactly that.
- **An Add-carrying Commit from a `PendingReverify` member takes a human step.** The bullet below admits a member's handshake traffic whatever its standing, and an Add is the one handshake message that grants a stranger membership — the same act the outbound gate above withholds. A member's Update, its Remove proposals, and its Add-free Commits are admitted unconditionally; a Commit that carries an Add proposal authored by a `PendingReverify` member is held and surfaced to the human, exactly as an outbound Add to a flagged identifier is. Admitting it would let a takeover the standing already reports place a second identity inside the context.
- **Every auto-accept gate reads a freshly resolved standing.** Before auto-accepting at the standing-pair consent gate, the known-identity allowlist, a cached `author_keys` entry, or any inbound path this bullet list names, the SDK MUST resolve that identifier's key-event log within `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7), and a log older than that bound fails closed to the manual path. **The §9.10.7 privacy cache never satisfies this check**, whose retention runs to 7 days for an inactive contact: a standing turns `PendingReverify` only when the SDK observes the change, so a gate reading a stored standing against a week-old resolution would auto-accept a taken-over identity for a week. The Add path carries this bound already as §9.7.1 check 2, and these gates carry the same one.
- **MLS handshake messages from an identifier that is already a member are admitted whatever its standing** — its Update proposals, its Remove proposals, and its Add-free Commits; a Commit carrying an Add takes the human step the bullet above states. A replaced leaf's attestation is checked against the adopted key state exactly as §9.7.1 check 1 always checks it. **Under a `Contested` verdict there is no adopted key state, and the leaf-replacing Update is held for the human instead** (§9.7.1, the `Contested` branch), which is the one exception this bullet carries. Standing is a judgement about the person behind an identifier, never about the bytes of a handshake. Blocking that traffic would foreclose §9.12's own remediation: step 2's Update and step 1a's Remove are the acts a recovering controller and its peers must perform, and every peer sets `PendingReverify` on the same `RootRecovery` that makes them necessary. MLS has no per-member send, so a reader that stopped content toward one `PendingReverify` member would stop the whole context.
- The standing returns to `Verified` when the user completes re-verification against the identity's current root set, by comparing the fingerprint above out of band. If fingerprints do not match on re-verification, a MITM is intercepting resolution or the identity has been taken over; the SDK MUST alert with maximum severity and the standing stays `PendingReverify`.
- **While the identity is `Contested`, the standing HOLDS at `PendingReverify` and no user act clears it.** A contested identity has no single current root set to verify a fingerprint against (§9.7.4.2 R7 forbids serving one), so a re-verification would be comparing against a chain the verifier has not adopted, and accepting the change by hand would clear the gate on exactly the takeover the contest reports. The SDK reports to the user that the identity is contested and why the exit is closed. R7's retirement of a resolved tie, above, is the only thing that clears it.
- For social recovery, trusted contacts independently confirm the change out of band before accepting it.

**Where each gate lives.** The bullet list above is authoritative for which acts the standing withholds; this paragraph names the section that owns each gate's implementation and adds no act. Three gates have their standing check written into the section that owns them: §9.7.1's admission and grant gates (Add, UCAN, sender key to a new leaf); §9.16.2 step 3's key response; and §9.6.4's first-contact bootstrapping. **Three gates do not yet carry their standing check, and this paragraph names where each one is missing rather than citing a section that carries it:**

- **The broadcast per-author key cache.** `.docs/specs/` defines no such cache: `05-contexts.md` §5.14.8 governs blocking in a broadcast context and names no `author_keys` entry, and no other section holds one. Both the cache and its standing check land in `05-contexts.md` §5.14 when the broadcast sender-key layer states where a subscriber holds an author's key.
- **The standing-pair consent gate.** The gate exists — `05-contexts.md` §5.15.8 states the steps peer B applies to an inbound standing-pair Welcome before it joins — and **no step of it reads a `ContinuityStanding`**. The check lands in that step list.
- **The known-identity allowlist.** The allowlist exists — `05-contexts.md` §5.12.2 makes a DID on the operator's explicit `known_did` list the sole auto-accept trigger — and **no clause of it reads a `ContinuityStanding`**. The check lands beside that trigger.

Each of the three MUST read the standing on a peer's `RootRecovery` when it lands, because a stable identifier keeps matching an allowlist entry that a rename used to invalidate. Until they do, the bullet list above is the whole enforceable gate set, and an implementer that builds a gate set from this paragraph alone would miss an act.

## 9.12 Compromise Recovery Protocol

When a key is known or suspected to be compromised, the following ordered steps constitute the recovery protocol:

**1. Key rotation on trusted device.**
- **A delegated agent identity's key compromise (most common case):** an agent runtime is typically less secure than a device HSM, so a delegated agent identity's `#active` is the most likely key in a human-plus-agent pair to be compromised. That identity runs the recovery protocol of this section on its own key-event log, because it holds its own root and its own operational key (§9.1 invariant 1). The human's `#active`, root UCANs, and root set are untouched, and the human revokes the scoped UCANs it issued to that agent identity (step 3). This is the cheapest recovery scenario for the human: no key of the human's changes.
- **Active Signing Key compromise (common case):** Generate a new active signing keypair; the standing root signs a `KeyState` (§9.7.4.2 R3) that lists the new `#active` `current` and the compromised key `Compromised{from: N}`, N = that `KeyState`'s sequence. **The position is what the log-anchored evidence class of §9.7.1 reads**; the content class bounds a key that is not `current` identically under all three non-`current` conditions, so recording that sequence is what stops the attacker from anchoring a destruction attestation or a durable snapshot behind the compromise, and not what bounds content. Every member of every context the identity belongs to runs step 1a on adopting that `KeyState`, which is what removes a leaf the attacker added under the stolen key. **The controller MUST then re-sign and republish its service record under the new `#active` before it destroys the old key** (`03-identity.md` §3.10.13, §3.2.1 case 1 step 3a-bis). `#active` is the key the designation resolves to, so every service record signed by the superseded key stops verifying the moment a reader adopts the `KeyState`, and a controller that skipped this step would leave the identity unroutable at every reader that adopted it. The identifier does not change. No root change is needed.
- **Root compromise (rare, severe), with or without operational-key compromise:** The controller signs a `RootRecovery` (§9.7.4.2 R3) with the pre-rotation key from independent custody — `standing_root: CoSigns` while it still holds a threshold of its root, `Lost` otherwise (§9.7.4.2 R10). The event installs a fresh root K′ generated under R10's device boundary and carries the complete post-recovery key state (§9.7.4.2 R8): every operational key by role — a fresh key for any key the compromised device also held, with the replaced key listed `Compromised{from: N}`, and the controller's own key re-listed otherwise; every other historical key re-listed in the condition it already carried, `Superseded` or `Retired`; the witness set; and the service-key designation, each diffed against the pre-compromise record per R10. The recovery carries no relay list: the controller re-points its relays by writing a service record under the newly designated key (§9.6.3, `03-identity.md` §3.10.13). The recovery supersedes any chain the attacker's root signed, wherever the attacker forked (§9.7.4.2 R6). The identifier does not change: no new identity is created and no forwarding record exists. Steps 1a–6 then run under the operational keys the snapshot names. **What the snapshot replaces is key state and nothing else.** It does not remove an MLS leaf the attacker added under the stolen `#active` in any context (step 1a covers it); it does not withdraw a KeyPackage the attacker published (the controller cannot enumerate them; they expire, and step 4 replaces the controller's own); it does not revoke a UCAN the attacker issued (step 3 covers the controller's tokens; §9.11's gate refuses a token issued **by** the flagged identifier, and one carrying it anywhere on the delegation chain, as each relying party encounters it, so no protocol enumeration of the attacker's tokens is needed); it does not undo auto-accept or contact-graph standing the attacker earned on peers, and §9.11's key-change rule is what withdraws it — the standing gates inbound auto-acceptance as well as outbound grants, so a peer that had auto-accepted the attacker stops doing so the moment it observes the recovery; it does not reach private-state events written under a stolen PSK (§3.7's re-key); and it does not withdraw an attestation the attacker issued (attestation verification is current-key-only, so the replaced key's attestations fail from the recovery on).
- **Pre-rotation key copied, root intact and trusted:** The controller signs a `CommitmentRollover` (§9.7.4.2 R3) immediately. The attacker can reveal the same commitment, so both suffixes are rank 1 and the identity is `Contested`, terminal by key material (§9.7.4.2 R7). A party's witness policy over a recognized-independent set is what resolves it, and §9.7.4.3 does not yet carry the witness protocol, so until that section lands the contest is terminal for every party and every peer holds the identifier at `PendingReverify` (§9.11). The rollover fixes a commitment the attacker cannot reveal, which stops the attempt from being repeated; it does not win the contest. The root's co-signature is evidence a witness policy weighs (§9.7.4.2 R6, Pin A) and never a rank: a rule that let a co-signature confer rank would hand a thief holding both the root and a copied pre-rotation key the win over a controller who lost its root and holds the genuine key, so the two-value rank keeps that case contested. No operational key changes, so for a rollover that fixes a commitment steps 1a–6 do not run; an abandoning rollover runs step 2 before it is published (§9.7.4.2 R4).
- **Retiring the identity (abandonment):** The controller, holding its root, issues the step-2 MLS Update in every context it belongs to, then publishes a `CommitmentRollover` declaring abandonment (§9.7.4.2 R4); each Commit is the abandonment boundary in its context (§9.7.1). Steps 3–6 do not run; relying parties that confirm the abandonment treat the identity's UCANs as revoked, its attestations as expired, and its sender keys as retired. If the controller suspects a copy of a pre-rotation key, it signs a `RootRecovery{CoSigns}` on its own suffix first and abandons under K′ (the failure-mode table). **What that order achieves and what it does not:** it consumes the standing commitment C first and installs K′, which forecloses the copy holder's extension past the commitment C′ that K′ fixes, so the copy cannot follow the identity forward. It does not end a contest, because the copy holder can still fork behind the `RootRecovery{CoSigns}`, reveal C there, and stand at rank 1 beside it (§9.7.4.2 R6). No order of key material retires an identity whose pre-rotation key was copied; the failure-mode table's copied-P row states the outcome and this bullet adds nothing to it.
- **Pre-rotation key copied, root lost:** The controller signs a `RootRecovery{Lost}`; the attacker can too, so both suffixes are rank 1 and the identity is `Contested` (§9.7.4.2 R7). Step 1a proposes Remove for no leaf while the contest stands, because R7 gives no party a `current` key state to test leaves against. Steps 2–6 run under the controller's suffix for the parties whose witness policy adopts it; for every other party the identity stays contested and `PendingReverify` (§9.11).
- **Pre-rotation key exclusively the attacker's, whatever the state of the root:** The attacker's `RootRecovery{Lost}` wins uncontested over the controller's chain, which reveals nothing (§9.7.4.2 R6; §9.7.4.1's failure-mode table). The root cannot be recovered by key material.
- **Root compromised with the pre-rotation key copied:** both parties can reveal, so the identity is contested (§9.7.4.2 R7). In every row where the root cannot be recovered by key material, a party's witness policy MAY still adopt the controller's suffix (§9.7.4.2 R6's slot); otherwise the person establishes a new identity, and each context's admins — after confirming the head from a relay in the fallback set, which the hostile identity's service record does not name (§9.7.4.2 R4, definitions) — remove the old identity and admit the new one; §3.3's social recovery does not apply, because it re-establishes custody of the same identity.
- **The controller's own identity is contested:** the SDK keeps extending the controller's suffix (§9.7.4.2 R10) and tells the human which suffix a witness policy over the recognized set would resolve for; it does not sign a further reveal, because both suffixes have already consumed the standing commitment.
- **Leaf-key / MLS-state compromise (ephemeral leaf key leaked, identity keys intact):** An attacker who extracts a member's MLS leaf state holds the leaf `signature_key`/`encryption_key` and the standalone **KeyPackage attestation** over them (§9.7.1). Beyond in-group PCS (§9.7.3), the standalone attestation lets the attacker reuse the leaf to join **other** groups until it expires. Remediation is an **existing operation, not a new mechanism**: the victim rotates `#active` by a `KeyState` signed by the standing root — the same rotation used for active-key compromise above — and every member of every affected context runs step 1a on adopting it, which is what evicts a leaf the attacker already placed in a group. This **invalidates every outstanding KeyPackage attestation within `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7 — 5 min, the hard current-key freshness bound of §9.7.1 check 2)** — near-immediate, not instantaneous — because every one of them was signed by the now-retired verification method and verifiers resolve the identity's `current` `#active` only (§9.7.1 check 1), from a key state no more than 5 minutes stale (§9.7.1 check 2); once the retired key no longer resolves (and no fresh-enough pre-rotation cache entry remains), every attestation signed by it fails verification at every Add, everywhere, within that bound. **An already-admitted member's Updates follow the Update posture instead** (§9.7.1, Resolution failure policy): a party that can sustain a resolution outage against the members of one context keeps that context on its last-known-good key state, and the honest upper bound there is `MAX_KEYPACKAGE_ATTESTATION_LIFETIME` (§9.18.7 — 84 days), not five minutes. The victim then re-issues fresh KeyPackages/attestations under the new key (step 4) and issues MLS Updates in active contexts (step 2). **Containment property:** a leaked *leaf* key does NOT expose `#active` — separating the ephemeral, context-scoped leaf key from the identity signing keys is the entire point of the attestation model (§9.7.4), so this recovery is a **routine key rotation, not an identity-key exposure**: no recovery event (§9.7.4.2), no pre-rotation-key consumption, no change of identifier. This is a **Tier-1 revocation** of the attestation: the key state already lists the `current` key, and rotating it is the sole, sufficient act that stops the leaf from joining further groups — **no `attestations_valid_after` watermark or other new key-state field is introduced** (a document-level revocation watermark was considered and rejected as over-engineering; rotation of an already-present key is a complete and cheaper revocation).

**1a. Leaf re-verification after a key-state change.** Every member of a context who **adopts** any state-carrying event for a fellow member — a `KeyState` or a `RootRecovery` — after which a leaf's attesting key is no longer `current` MUST re-verify every leaf in that group carrying that identity against the adopted key state. **The Remove test is the signature test, and it carries a grace:** the member proposes Remove for a leaf when the leaf's KeyPackage attestation does not verify against the key the adopted state lists `current` for the `signing_key_id` that leaf names (§9.7.1 check 3) **and** the identity has committed no replacement leaf in that group within `LEAF_REPLACEMENT_GRACE` (§9.18.17) of the member adopting the state-carrying event. Comparing the `signing_key_id` fragment instead would evict nothing, because every leaf names `#active`, and the snapshot lists a fresh key under that same fragment.

**The grace exists because the signature test alone cannot tell two leaves apart.** After an identity rotates `#active`, two leaves in a context fail the test identically: an attacker's leaf, attested under the stolen retired key, and the identity's **own live leaf**, attested under the retired key because its replacement is step 2's Update, which has not committed yet. A peer that adopted the `KeyState` on its own resolution cycle before that Update landed would propose Remove for both, and a planned custody migration (`03-identity.md` §3.2.1 case 1) would evict the migrating member from its own context. The grace gives the identity one leaf-replacement interval to commit the Update, and the recovering controller's own enumeration below closes the grace early for the leaves it names, because the controller holds evidence a peer does not. A PCS Update heals a leaked leaf secret and does not evict a member, so this step is the only thing that removes a leaf the attacker added — and the most common compromise, `#active`, is remediated by a `KeyState`, so a step that fired only on a `RootRecovery` would leave the attacker's leaf in place for exactly that case.

**On a `Contested` verdict this step proposes Remove for no leaf.** R7 forbids a contested identity a `current` key state, so no member holds the basis the signature test reads, and three members applying the step to a contested identity would evict three different sets of leaves. A member holds the contested verdict, withholds the acts §9.11 names, and waits for the contest to resolve.

The recovering controller's own SDK MUST enumerate every leaf under its identity in every context it can reach and propose Remove for each one whose attestation it did not sign, and it proposes those Removes without waiting out `LEAF_REPLACEMENT_GRACE`, because "an attestation I did not sign" is a discriminator only the controller holds. Where the attacker is the sole admin of a context, no member can issue the Remove and the context is re-created (§5.9); that outcome is stated, not hidden.

**2. MLS Update in all active contexts.** Issue MLS Update proposals in every context. This Commit is the identity's compromise boundary in that context (§9.7.1), and every member records that epoch as the retired key's boundary value so a later context snapshot or export carries it to members who did not observe the Commit (§9.7.1). This provides post-compromise security: new epoch keys are derived from the new key material, making the compromised old key useless for future messages. If the old key is unavailable (device stolen), a trusted co-member with admin role must remove and re-add the member. **In a context where no Commit ever records the retirement** — the controller cannot reach it, or the step-ordering paragraph below flags it for manual re-join — that context's log records no retirement Commit for the key, so §9.7.1 makes the absence a fact about the context rather than a gap: its members read their Commit history, find none, and keep verifying that key's content there. A rule that rejected instead would discard every message and every governance vote that identity ever signed in that context, which is the outcome §9.7.1's content class exists to prevent.

**3. UCAN revocation.** Revoke all UCAN tokens issued by the compromised key. Add revocations to each context's `RevocationList` and distribute via MLS application messages (§9.5). Issue new tokens signed by the new key.

**4. KeyPackage attestation rotation.** Delete all outstanding KeyPackages carrying an attestation signed by the old `#active` key from relays. Publish fresh KeyPackages whose leaves carry **KeyPackage attestations re-issued under the new key** (§9.7.1). The KeyPackage leaves themselves remain self-signed by their ephemeral MLS leaf signature keys — it is the attestation, not the KeyPackage/leaf, that the rotated DID key re-signs.

**5. Contact notification.** The SDK sends a key-change notification to all known contacts. Contacts who completed Key Continuity Verification (§9.11) are alerted that re-verification is needed. A recovery event (§9.7.4.2 R3) changes the root key without changing the identifier, so the identifier itself no longer signals that the root moved; a relying party re-verifies key continuity (§9.11) on every recovery event.

**6. Identity private state re-encryption.** Re-encrypt identity private state (§3.7) under the new key. Publish re-encrypted state to relays.

**Step ordering and failure isolation:** Steps 1-6 are ordered by dependency: key rotation (1) must complete before MLS Updates (2) because Updates use the new key material; MLS Updates (2) must complete before UCAN revocation/reissuance (3) because new UCAN tokens are signed by the new key; KeyPackage attestation rotation (4) must follow to prevent new group additions using old key material; steps 5 and 6 are cleanup and can execute in any order after step 4. Steps 2-4 are per-context — failure in one context does not block recovery in other contexts. The SDK retries failed contexts independently. A context where MLS Update cannot succeed (e.g., member has been offline too long and requires Tier 3 re-join per ADR-029) is flagged for manual re-join and does not block recovery in other contexts.

**Time-shifted key compromise:** An attacker who extracts MLS state at time T can read messages **in the compromised group** until the next PCS Update. Forward secrecy protects all messages from before T (old epoch keys already deleted). PCS protects all messages after the next Update in that group. The **in-group** vulnerability window is therefore bounded by the PCS Update interval (§9.7.3).

This PCS bound is **in-group only**, and it does NOT bound a second vector: the compromise of a leaf key together with its **standalone KeyPackage attestation**. A PCS Update heals the group the victim is currently in, but it does **not** invalidate the standalone attestation, which an attacker holding the leaf's `signature_key`/`encryption_key` can reuse to join **other** groups. That reuse is bounded not by any group's PCS interval but by two independent controls: (1) the attestation's own capped lifetime — `expires_at - issued_at <= MAX_KEYPACKAGE_ATTESTATION_LIFETIME` (§9.18.7), after which the attestation is rejected everywhere on freshness; and (2) **`#active` rotation** (§9.12 "leaf-key / MLS-state compromise"), which invalidates every outstanding attestation **within `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7 — 5 min)** — near-immediate but not instantaneous (§9.7.1 checks 1–2, "Resolution failure policy") — because verifiers resolve the signer's **current** verification method only (§9.7.1 check 1), from a key state no more than 5 minutes stale (§9.7.1 check 2). **That bound covers every Add, everywhere.** An already-admitted member's Updates follow the Update posture of §9.7.1's Resolution failure policy, whose honest upper bound under a sustained resolution outage is the attestation lifetime cap. Rotation is the fast lever on the Add path; the lifetime cap is the backstop, and it is also the real bound on the Update path against an attacker who can degrade resolution.

## 9.13 Transport Security Requirements

**Relay connections MUST use TLS 1.3** (or higher). TLS 1.2 is acceptable only as a fallback when TLS 1.3 is unavailable.

**Certificate validation:** Standard WebPKI validation. The SDK MUST reject self-signed certificates for relay connections unless the user has explicitly configured a self-hosted relay with a pinned certificate.

**Certificate pinning:** The SDK SHOULD support certificate pinning for known relays.

**Relay authentication:** SCP does not depend on relay authentication — encryption-as-access-control (§10.5) makes it unnecessary for confidentiality. Individual transport adapters may support adapter-specific authentication mechanisms (e.g., NIP-42 for Nostr relays). Relay authentication may be useful for relays that want to limit their user base or implement per-user rate limiting.

**Direct connections:** For the direct WebSocket transport adapter, connections between devices MUST use TLS (wss://) unless both devices are on the same local network AND the user has explicitly accepted the risk.

**Self-hosted relay exception:** **a relay URL may use `ws://` if and only if the resolver took it from a service record whose signature it verified against the designated service key of a key-event log it verified under §9.7.4.2 R2 and R3** — the log authenticates the designated key and that key authenticates the relay list, so the two verifications together make the URL self-certifying, whichever relay served either object (§9.6.1, §9.6.3, `03-identity.md` §3.10.13). The SDK MUST reject a `ws://` relay URL from every other source, `.well-known/scp` and an unverified service record among them, because such a source carries no signature binding the URL to the identity and a substituted URL would downgrade the transport unnoticed. This section is the one home of that criterion, and §10.12.6 applies it to the self-hosted relay tiers by citation. Such relays have no domain and cannot obtain CA-signed certificates; MLS provides the confidentiality boundary, and TLS on a dumb pipe protects already-encrypted traffic.

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
  context_id:            String
  member_did:            DID
  destroyed_at:          DateTime
  key_state_head:        [u8; 32]              // §9.7.1's log-anchored row constructs this value
  platform_attestation:  PlatformAttestation?  // hardware-backed if available
  method:                .hardwareBacked | .softwareOnly
  signature:             Ed25519Signature       // signed by #active (Active Signing Key); NOT a root member (the root signs establishment events only, §9.7.4.2 definitions)
}
```

§9.5.2 fixes the field order and encoding of the signed preimage, and every field above except `signature` is inside it — `key_state_head` included, so the anchoring position is signed rather than supplied beside the signature. **A human identity's own `#active` signs a destruction attestation, and a delegated agent identity MUST NOT sign one**: an agent destroys no context's key material on the human's behalf, and a verifier rejects a destruction attestation signed under a delegated identity.

4. Attestations are published to relays, outside the now-destroyed context, so they remain readable after the context keys are destroyed. They are **log-anchored evidence** (§9.7.1): the `key_state_head` field carries the value §9.7.1's log-anchored row constructs, and a verifier accepts the signature iff the signing `#active` was `current` at that position. A later routine rotation of `#active` therefore leaves every earlier destruction attestation verifiable, which is the property the attestation class would not give it — a signer that could void its own past destruction claims by rotating a key it controls would be publishing no evidence at all. **Where the key state lists the signing key `Compromised{from: N}`, the anchor alone proves nothing**, because the signer chooses `key_state_head` and the holder of a compromised key chooses a position before N. §9.7.1 states the two conditions under which a verifier accepts such an artifact — it held the artifact before it adopted the event carrying N, or a party independent of the signer countersigned it — and states that the class gives no guarantee where neither holds.

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

**Receive-side replay detection.** Recipients MUST maintain a per-sender `(last_epoch, last_sequence)` tracker and per-sender epoch high-water mark. Messages with `epoch < last_epoch` or `(epoch == last_epoch && sequence <= last_sequence)` MUST be rejected as replays. This provides defense-in-depth alongside MLS-layer replay protection. This receive-side state is persisted **only** in the node-local crypto-state snapshot (warm-restart / crash recovery on the *same* node — §17.9.1 MLS Crypto State Snapshot, restored under the floor-preservation rule of §23.17 Invariant 2). It MUST NOT be adopted as authoritative from a portable cross-party context export (§23.16.8): receive-side freshness state has no authority on a foreign node, so an importer establishes its receive window per the §23.17 import-floor invariants (Invariant 3/4 — take `max` with the local floor, never lower it; a node with no prior state for that sender therefore starts a fresh receive window). Inheriting a foreign exporter's tracker verbatim would let a validly-signed but hostile exporter pre-load receive-side state and bypass the epoch-poisoning ceiling below. A node that cannot persist a local crypto snapshot (e.g. an ephemeral, storage-less session) maintains the tracker for the duration of its session only and starts fresh on each (re)establishment.

**Epoch poisoning defense.** Recipients MUST reject sender key distributions with `epoch > current_epoch + 1000`. This prevents an attacker from setting an artificially high epoch (e.g., `u64::MAX`) to permanently block future legitimate key rotations via the epoch monotonicity check.

**Management messages.** MLS application messages may carry management payloads (e.g., sender key distributions during key rotation) instead of application content. Management messages are distinguished by a 4-byte ASCII magic prefix:

```
SCPM_MAGIC = [0x53, 0x43, 0x50, 0x4D]  ("SCPM" — Shared Context Protocol Management)
```

Management message MLS plaintext format: `SCPM_MAGIC (4 bytes) || management_payload`. Management messages bypass the sender-key encryption layer entirely — they are MLS-encrypted only, with authentication provided by MLS group membership. Recipients check the first 4 bytes of the MLS plaintext after decryption: if they match `SCPM_MAGIC`, the message is routed to management message processing; otherwise, it is parsed as a sender-key-encrypted application message (16-byte header + ciphertext). The epoch value in an application message header starts at 1 and increments monotonically, so the first 4 bytes (`0x00000000` for epoch ≤ 255) can never collide with `SCPM_MAGIC` (`0x5343504D`). Management payloads MUST NOT exceed 65,536 bytes (64 KiB).

**Management prefix exclusivity.** The `SCPM_MAGIC` check MUST occur **exactly once** per incoming message, at the MLS plaintext → application message boundary described above. No other layer — transport, relay, outer-envelope processing, sender-key decryption, or any post-dispatch application code — is permitted to strip, test, or otherwise depend on the magic prefix. Implementations MUST centralize this check to a single call site to preserve the single-responsibility invariant that motivates the framing: message type is a property of MLS plaintext, not of any other layer. Conformance implementations MAY share the check between a production crypto provider and a test-equivalent provider, provided both invoke the same canonical helper. Duplicating the check elsewhere in the pipeline is a protocol violation.

**Wrapping key terminology.** The sender-side key layer uses two distinct wrapping keys, both HPKE-based (RFC 9180 Base mode, §9.5) but serving different roles: (1) the **stable wrapping keypair** (below) protects the persistent per-sender AES-256 symmetric key during key distribution — it is long-lived and published in the MLS LeafNode; (2) the **ephemeral wrapping keypair** (§9.16.2) protects per-request key material during individual key exchanges — it is generated fresh for each `SenderKeyRequest` and discarded after use. Both use X25519 DHKEM + HPKE for key encapsulation, but the stable key enables offline key distribution while the ephemeral key provides forward secrecy for individual key exchanges.

**Stable wrapping keypair.** Each member maintains a single dedicated X25519 keypair per context (one per identity, because a delegated agent identity joins a context as its own member and publishes its own wrapping key), used exclusively for HPKE wrapping of sender key distributions (§9.16.2). This keypair is published as an MLS LeafNode extension (`scp_wrapping_key`) and is distinct from the MLS leaf HPKE key used for MLS key agreement. The wrapping keypair does NOT rotate on MLS Updates (epoch advances) — it remains stable across epochs so that sender key distributions can always be unwrapped, even by members who are offline during epoch transitions or who join after an epoch advance. The wrapping keypair rotates only on: (1) identity key rotation (§9.12), or (2) suspected compromise. On rotation, the member publishes the new wrapping public key in their LeafNode extension via an MLS Update and re-distributes their current sender key to all non-blocked members using the new wrapping keys.

### 9.16.2 Key Distribution (Pull-Based)

Sender keys are distributed via a pull-based request/response protocol. When a sender generates or rotates a key, they publish a lightweight epoch advance notification as an MLS application message. Members request the actual key material on demand via directed MLS application messages. This replaces a push-based model where the sender would HPKE-encrypt the key to every recipient in a single message — the pull model reduces block cost from O(N) to O(1) on the sender side and naturally load-balances key distribution.

**Protocol flow:**

1. **Epoch advance notification.** When a sender generates or rotates their key, they publish a `SenderKeyEpochAdvance { sender_did, epoch, signature }` as an MLS application message. The signature covers `context_id || sender_did || "key_epoch" || epoch`, signed by the sender's Active Signing Key (`#active`). This is **O(1)** regardless of group size.

2. **Key request.** Members who need the key (because they see a new epoch, or because they just joined) send a `SenderKeyRequest { requester_did, sender_did, epoch, wrapping_pubkey, signature }` as an MLS application message with `recipient_hint` directed to the key holder. The `wrapping_pubkey` is a fresh ephemeral X25519 key generated per request.

3. **Key response.** The key holder's SDK processes the request: verifies the signature, checks the block list, and reads the requester's `ContinuityStanding` (§9.11) — a sender key is never distributed to a **new leaf** of an identifier whose standing is `PendingReverify`, while a leaf that already holds the key keeps it, because withholding from an existing member would stop the context rather than the takeover. If the requester is not blocked, responds with `SenderKeyResponse { sender_did, epoch, hpke_sealed_key, ephemeral_pubkey, request_nonce }` via an MLS application message with `recipient_hint` to the requester. The sender key is sealed using HPKE Base mode (RFC 9180) to the requester's ephemeral wrapping public key. If blocked, no response — the blocked party cannot obtain the key. The `ephemeral_pubkey` field carries the HPKE encapsulated key (`enc` in RFC 9180 terminology) and `hpke_sealed_key` carries the AEAD ciphertext (`ct`).

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

1. Compute the KEM Diffie-Hellman output `dh = DH(wrapping_secret_key, enc)` inside the `KeyCustody` boundary via `dh_agree(wrapping_key_handle, enc)`, where `enc` is the `ephemeral_pubkey` from the response. The wrapping private key never leaves custody — only the raw `dh` output (and the recipient's own public key `pkRm`, obtained via `KeyCustody::public_key(wrapping_key_handle)`) cross the boundary. RFC 9180 DHKEM Decap then completes outside custody: `shared_secret = ExtractAndExpand(dh, enc || pkRm)` (RFC 9180 §4.1), binding both `enc` and `pkRm` into the KEM shared secret. This is equivalent to `SetupBaseR(enc, wrapping_secret_key, info)` (RFC 9180 §5.1.1) for software-held keys, but splits the single non-extractable scalar multiplication into custody while keeping the rest of Decap + KeySchedule in software.
2. Run `KeySchedule_base` over `shared_secret` and `info` to derive the AEAD `key`/`base_nonce`, then `Open(aad, ct)` to recover `sender_key_bytes`, where `ct` is the `hpke_sealed_key` from the response.

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
4. Alice sends a **signed** block notification to Bob as an MLS application message: `{"type": "block", "blocker": "<Alice's identifier>", "blocked": "<Bob's identifier>", "signing_key_id": "#active", "timestamp": unix_ms, "signature": "<Ed25519>"}`. The signature covers the canonical hash `SHA-256("SCP-BLOCK-NOTIFICATION-V1:" || len(context_id) || context_id || len(blocker_did) || blocker_did || len(blocked_did) || blocked_did || len(signing_key_id) || signing_key_id || timestamp_BE)` — see the BlockNotification row in §9.5.2 for field order and encoding. `alice_signing_key` is Alice's Active Signing Key (`#active`); the `signing_key_id` field tells the verifier which verification method of Alice's key state to resolve. The signature prevents forgery — without it, any group member could impersonate Alice and trick Bob into rotating his sender key. MLS application messages prove group membership but not individual sender identity within the message payload.
5. Non-blocked members observe the epoch advance and send `SenderKeyRequest` for Alice's new key (§9.16.2). Alice's SDK checks the block list for each request — responds with the HPKE-encrypted key for non-blocked members, ignores requests from Bob. **O(1) per response.** For global blocks (Tier 2), Alice's SDK checks the identity-level block list directly — not only the per-context block list — to prevent bypass via context-level propagation delays.
6. Bob's client **verifies the block notification signature** by resolving the public key identified by the notification's `signing_key_id` from Alice's key state (`#active`). If verification fails, the notification is discarded and logged for anomaly detection. If verification succeeds, Bob's client automatically rotates Bob's sender key (incrementing his own epoch), publishes his own `SenderKeyEpochAdvance`, and adds Alice to Bob's block list. When members request Bob's new key, Bob's SDK responds to everyone except Alice.
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

**Sender key epoch counter.** Each sender maintains a monotonic `sender_key_epoch` counter (starting at 1 on key generation, incremented on each rotation; §9.16.1 relies on the first-message epoch being ≥ 1 so its big-endian header prefix can never collide with `SCPM_MAGIC`). The epoch counter is included in `SenderKeyEpochAdvance` notifications and `SenderKeyRequest`/`SenderKeyResponse` messages. This enables members to detect missed rotations (gap in observed epochs), detect stale keys (epoch lower than expected), and correctly associate cached keys with the epoch they belong to. The `KeyEpochAdvance` event type (ADR-011) records epoch advances in the context event log for auditability.

### 9.16.6 Sybil Resistance at the Blocking Layer

The block list (§9.16.3) is per-identity. A Sybil attacker — one human controlling several identities — can create a fresh identity that no block list names and use it to request the new sender key after a block event. An agent is a separate delegated identity, and its key state names the delegator that anchors it (§9.7.4.2 definitions), so the delegation anchor ties each agent identity to one human identity and a blocker reads that anchor from either chain. The Sybil cost of an agent identity is therefore the cost of the human identity whose chain anchors it, which is how key material carries the "every agent traces to a human" tenet. The block list alone does not prevent all bypass. This section specifies the mitigations.

**Mitigation 1: Membership gate.** `handle_sender_key_request` MUST verify that the requester's DID is a current member of the context before distributing sender keys. In Encrypted contexts, MLS group membership already gates who can observe application messages (including `SenderKeyRequest`), so this is defense-in-depth redundancy. In Broadcast contexts, where key requests travel as relay messages outside MLS, the membership gate is the primary defense: a Sybil DID that has not been admitted through normal subscription controls (DID-authentication for open contexts, UCAN validation for gated contexts) cannot request keys. The Sybil attacker must first pass the context's admission controls — earned capacity thresholds, UCAN gating, device attestation requirements, or whatever the context mandates — before they can even attempt a key request. This raises the cost of Sybil bypass from "create a DID" to "create a DID AND satisfy context admission requirements."

**Mitigation 2: Identity-linked block expansion.** When blocking a DID, the blocker's SDK SHOULD expand the block list to include all DIDs known to be linked to the same identity. Identity linkage sources include:
- **Delegation anchors** (§9.7.4.2 definitions): a delegated identity's key state names its delegator, and the delegator's chain carries the key-event seal that anchors the delegate, so a blocker who blocks either end reads the other from the chain.
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

**Access key request protocol.** `AccessKeyRequest` messages MUST include a signed payload: `{ context_id, requester_did, epoch, timestamp, nonce }` signed with the requester's Active Signing Key (`#active`). The `nonce` is a 16-byte random value, unique per request. The responder verifies the signature, checks the block list and revocation list, and responds with the HPKE-encrypted access key only if the requester is authorized. **Replay prevention:** The responder validates that the request timestamp is not older than 300 seconds (5 minutes, consistent with the protocol-wide clock skew tolerance §9.14) and not more than 30 seconds in the future (tighter bound — future timestamps indicate clock manipulation rather than legitimate network delay). The responder also verifies that the `nonce` has not been previously seen. The responder maintains a nonce deduplication cache with a 5-minute TTL — nonces are single-use and cached for the duration of the validity window. Requests with expired timestamps or duplicate nonces are rejected.

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

All domain separators are UTF-8 strings used as prefixes in canonical hash, signature-preimage, or key/id-derivation constructions (§9.5.1 governs signature preimages; other constructions — key/id-derivation domains and id-construction prefixes — are noted per row). Most entries are §9.5.1 field-enumerated signature-preimage separators; the table also includes non-§9.5.1 entries (for example the `"standing:"` / `"standing-"` context-id construction prefixes, §5.15.8), and §9.4.3 directs a future secret-bearing saga to register its `"scp/saga-commit/<saga-type>/v1"` commitment separator (a commitment-hash domain, also non-§9.5.1) here. Each separator identifies the struct or derivation being hashed to prevent cross-protocol hash confusion.

| Domain Separator | Used For | Spec Reference |
|------------------|----------|----------------|
| `"SCP-INNER-ENVELOPE-V1:"` | InnerEnvelope signing | §9.5.2 |
| `"SCP-BROADCAST-ENVELOPE-V1:"` | BroadcastEnvelope signing | §9.5.2 |
| `"SCP-EPOCH-ADVANCE-V1:"` | SenderKeyEpochAdvance signing | §9.5.2 |
| `"SCP-KEY-REQUEST-V1:"` | SenderKeyRequest signing | §9.5.2 |
| `"SCP-ATTESTATION-V1:"` | Attestation signing | §9.5.2 |
| `"SCP-KEYPACKAGE-ATTESTATION-V1:"` | KeyPackage attestation (ephemeral MLS leaf key ↔ DID binding) signing | §9.5.2 |
| `"SCP-PARTICIPATION-V1:"` | ParticipationProfile signing | §9.5.2 |
| `"SCP-PARTICIPATION-PROFILE-V1:"` | ParticipationProfile canonical hash | §9.5.2 |
| `"SCP-BLOCK-NOTIFICATION-V1:"` | BlockNotification signing | §9.5.2 |
| `"SCP-ACCESS-KEY-REQUEST-V1:"` | AccessKeyRequest signing | §9.5.2 |
| `"SCP-VOTE-V1:"` | Governance vote signing | §9.5.2 |
| `"SCP-PROPOSAL-V1:"` | Governance proposal ID computation | §9.5.2 |
| `"SCP-MIGRATION-V1:"` | DID migration proof — **retired**: no migration proof exists in the key-event-log model, because a root-key change is a `RootRecovery` signed under `"SCP-KEL-EVENT-V1:"` | §9.7.4.2 R13 |
| `"SCP-KEL-EVENT-V1:"` | Key-event signature preimage for every key-event kind — `Inception`, `KeyState`, `CommitmentRollover`, `RootRecovery` (§9.7.4.2 R3); the first field after the separator is the event-type discriminator byte | §9.7.4.2 R13 |
| `"SCP-PREROTATION-COMMITMENT-V1:"` | Pre-rotation commitment over the fixed-length pre-rotation public key — a commitment-hash domain, NOT a §9.5.1 signature-preimage separator | §9.7.4.2 definitions, R13 |
| `"SCP-KEL-SEAL-V1:"` | Key-event seal — `SHA-256("SCP-KEL-SEAL-V1:" \|\| anchored_event_preimage_digest)`, carried by a `KeyState` to anchor another identity's key event (the delegation use); a commitment-hash domain, NOT a §9.5.1 signature-preimage separator, and never a content anchor | §9.7.4.2 definitions, R13 |
| `"SCP-KEL-ID-V1:"` | Inception-derived identifier — `SHA-256("SCP-KEL-ID-V1:" \|\| inception_signed_preimage)`, with the inception's identifier and predecessor-digest fields set to the all-zero placeholder; an identifier-construction prefix, NOT a §9.5.1 signature-preimage separator | §9.7.4.2 R13 |
| `"SCP-SERVICE-RECORD-V1:"` | Signature preimage of the service record — `SHA-256("SCP-SERVICE-RECORD-V1:" \|\| identifier \|\| sequence \|\| entries)`, signed by the operational key the key state designates for the service record | `03-identity.md` §3.10.13 |
| `"scp:did:"` | Key-event record routing derivation — `SHA-256("scp:did:" \|\| identifier_bytes)`; an id-derivation domain, NOT a §9.5.1 signature-preimage separator | §9.7.4.2 R13 |
| `"scp:svc:"` | Service-record routing derivation — `SHA-256("scp:svc:" \|\| identifier_bytes)`; an id-derivation domain, NOT a §9.5.1 signature-preimage separator | `03-identity.md` §3.10.13 |
| `"SCP-RESET-REQUEST-V1:"` | Sync reset request signing | §23.5.2 |
| `"SCP-KEY-CONTINUITY-V1:"` | Key continuity fingerprint hash | §9.11 |
| `"SCP-CHECKPOINT-V1:"` | Event log checkpoint hash — **content class** (§9.7.1): a member accepts a checkpoint through MLS inside the context, so the context epoch orders it | §11 |
| `"SCP-EVENT-V1:"` | Event log entry hash | §11 |
| `"SCP-EXPORT-ENTRY:"` | Context export chain hash | §5.13 |
| `"SCP-OUTLET-REGISTRATION-V2:"` | Outlet registration integrity hash | §6.2 |
| `"SCP-KEY-DESTRUCTION-V1:"` | Key destruction proof — the one **log-anchored evidence** separator (§9.7.1): the artifact carries the digest of the signer's key-state head at signing, and it verifies against the key that was `current` at that position | §9.15 |
| `"SCP-CLAIM-V1:"` | Shadow identity claim validation | §12.3 |
| `"SCP-RECEIPT-V1:"` | Payment receipt signing | §19.15.5 |
| `"SCP-HANDLE-OUTLET-V1:"` | Handle and scope outlet request signing | §22.3.1, §22.3.5 |
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
| `"SCP-CONTEXT-SNAPSHOT-V2:"` | Tier-2 sync-delta context snapshot signing; the `-V2:` preimage carries `key_state_head` | §23.16.4 |
| `"SCP-CONTEXT-EXPORT-V2:"` | Signed context export snapshot signing; the `-V2:` preimage carries `key_state_head` | §23.16.8 |
| `"SCP-XCTX-RECEIPT-V1:"` | Cross-context outlet receipt signing | §6.2.4 |
| `"SCP-XCTX-DIVERGENCE-V1:"` | Cross-context divergence marker signing | §6.2.4 |
| `"SCP-OUTLET-CHUNK-SIG-V1:"` | Per-chunk operator signature (outlet stream) | §5.4.5 |
| `"SCP-OUTLET-CHUNK-V1:"` | Outlet-stream chunk Merkle manifest leaf/interior domain | §5.4.5 |
| `"SCP-OUTLET-CAVEAT-BIND-V1:"` | Outlet-stream caveats-binding preimage (`ucan_cid`/`request_id`/`invoker_did`/`estimated_chunk_count`/narrowed caveats) | §5.4.5 |
| `"SCP-OUTLET-CREDIT-V1:"` | Outlet-stream credit-grant signing preimage | §5.4.5 |
| `"SCP-OUTLET-CANCEL-V1:"` | Outlet-stream cancel signing preimage | §5.4.5 |
| `"SCP-XCTX-STREAM-RECEIPT-V1:"` | Cross-context streaming-saga receipt signing | §6.2.5 |
| `"SCP-INVITATION-BUNDLE-V1:"` | InvitationBundle signing — over the full genesis `ContextParams` (per-field JCS hashes) | §5.12.3.1 |
| `"SCP-JOIN-RESPONSE-V1:"` | JoinResponse signing | §5.12.3.2 |
| `"standing:"` / `"standing-"` | Standing-pair context-id derivation prefix — internal id construction over a §9.5.1 length-prefixed body, NOT a §9.5.1 signature-preimage separator (`"standing-"` is an output id-prefix) | §5.15.8 |

#### 9.18.3 Key Derivation and HPKE Labels

This section consolidates all HKDF labels, HPKE info prefixes, HMAC domain strings, and MLS exporter labels. Each label provides domain separation for a specific key derivation or encapsulation protocol.

**HPKE info prefixes** — used in `info` parameter of RFC 9180 HPKE encapsulation:

| Info Prefix | Used For | Full Format | Spec Reference |
|-------------|----------|-------------|----------------|
| `"scp-sender-key-v1"` | Sender key HPKE encapsulation | `"scp-sender-key-v1" \|\| BE32(len(context_id)) \|\| context_id \|\| BE32(len(sender_did)) \|\| sender_did \|\| epoch_BE` | §9.16.2 |
| `"scp-access-key-v1"` | Access key HPKE encapsulation | `"scp-access-key-v1" \|\| BE32(len(context_id)) \|\| context_id \|\| BE32(len(member_did)) \|\| member_did \|\| epoch_bytes` | §9.17.1 |
| `"scp-broadcast-key-v1"` | Broadcast key HPKE encapsulation | `"scp-broadcast-key-v1" \|\| BE32(len(context_id)) \|\| context_id \|\| BE32(len(author_did)) \|\| author_did \|\| epoch_bytes` | §5.14.2 |
| `"scp-invitation-v1"` | Invitation/join HPKE encapsulation | `"scp-invitation-v1" \|\| BE32(len(context_id)) \|\| context_id \|\| BE32(len(creator_did)) \|\| creator_did` | §5.12.3.1 |
| `"scp-private-state-v1"` | PSK distribution HPKE encapsulation | `"scp-private-state-v1" \|\| BE32(len(did)) \|\| did \|\| purpose` where `purpose` ∈ {`"device-enroll"`, `"psk-rotate"`} | §3.7.2 |

`"scp-invitation-aad-v1"` is an AEAD-AAD domain string (not an HPKE `info` prefix): `aad = "scp-invitation-aad-v1" \|\| BE32(len(context_id)) \|\| context_id \|\| BE32(len(creator_did)) \|\| creator_did` (§5.12.3.1). The broadcast-key and access-key `aad` strings reuse the `info` field encoding without the domain-separator prefix (§5.14.2, §9.17.1).

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
| Max outlet interfaces per context | 256 | Hard cap on registered outlet interfaces | §6.2 |
| Ceiling change notification period | 259,200s (72h) | Members notified before ceiling change takes effect | §5.3.2 |
| Freeze timeout | 172,800s (48h) | Frozen context auto-unfreezes after this period | §5.6 |
| Default context verification window | 300s (5 min) | Grace period for context close verification | §5.6 |
| Outlet lifecycle default timeout | 30,000ms (30s) | Default outlet invocation timeout | §6.2 |
| Outlet lifecycle max timeout | 300,000ms (5 min) | Hard protocol maximum for outlet invocation timeout | §6.2 |
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
| MLS extension type: `scp_context_params` | `0xFF02` | RFC 9420 §17.3 private-use range; GroupContext extension carrying JCS-serialized SCP Context Parameters (context_id, governance/ceiling hashes, parent lineage) | §5.13.3 |
| MLS extension type: `scp_keypackage_attestation` | `0xFF03` | RFC 9420 §17.3 private-use range; LeafNode extension carrying the KeyPackage attestation binding **all** of the leaf's public keys — the ephemeral leaf `signature_key`, the LeafNode ratchet-tree `encryption_key`, the KeyPackage `init_key`, and the `scp_wrapping_key` `wrapping_key` — to the member's DID (`#active`-signed) | §9.7.1 |
| `MAX_KEYPACKAGE_ATTESTATION_LIFETIME` | 7,261,200s (84 days + 1h) | Maximum accepted `expires_at - issued_at` for a KeyPackage attestation (§9.7.1 verifier check 12). **Tied to the existing leaf/KeyPackage `Lifetime` maximum range** — SCP already bounds a leaf `Lifetime` to `KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS = KEY_PACKAGE_LIFETIME_MARGIN_SECS (3,600s / 1h) + KEY_PACKAGE_LIFETIME_SECS (7,257,600s / 84 days)` (ADR-057 Prereq-1; mirrors openmls `MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS`). Because §9.7.1 check 11 pins the attestation window to `[Lifetime.not_before, Lifetime.not_after]`, the attestation's max range MUST equal that leaf-Lifetime max range — a tighter attestation cap would reject every honestly-minted leaf, and a wider one would let a self-asserted attestation outlive its leaf. This makes the previously-implicit bound explicit and verifier-checkable without separately re-validating the leaf `Lifetime`, bounding the standalone-attestation reuse window after a leaf-key compromise (§9.7.3, §9.12). | §9.7.1 |
| `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` | 300s (5 min) | Maximum age of the resolved key state used to satisfy the KeyPackage-attestation **current-key** check (§9.7.1 verifier checks 1–2), and the same bound the §9.11 auto-accept gates and the §9.7.1 content-signature path read. Tied to the §9.14 clock-skew tolerance (also 5 min). A resolver-cache entry older than this MUST NOT satisfy the current-key check — it MUST trigger a fresh resolution (on an Add a resolution failure then rejects; on an already-admitted member's Update a transient failure falls to the bounded last-known-good grace — §9.7.1 "Resolution failure policy"). This hard-bounds attestation-revocation latency on the Add path after `#active` rotation (§9.12) and is **decoupled from — and far tighter than — the §9.10.7 DID-resolution privacy cache TTL (24h / 7d)**, which MUST NOT be used to satisfy the current-key check beyond this bound. | §9.7.1 |
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
| Key-event record frame version | 2 | Current key-event record relay frame version (§9.10.12); bumped on any field-encoding change. §9.10.12's `version` bullet states why this frame starts at 2, and this row restates none of it. The frame has no magic tag and no record-kind byte — the identity's `routing_id` domain is the type discriminant. Unsigned framing — grants no authority. See also §9.18.11 Transport and Relay for the shared blob-size/TTL bounds the frame reuses. | §9.10.12 |
| Key-event record frame fixed prefix | 33 | Fixed-width prefix length in bytes (`version` 1 + `identifier` 32); the frame carries no signature and no sequence field, and `value` is the trailing remainder, `total_frame_len = 33 + len(value)` | §9.10.12 |
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
| Max context writers | 500 | Maximum writer members in a context with discovery outlets | §22.3 |
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

#### 9.18.17 Key-Event Log

| Constant | Value | Notes | Spec Reference |
|----------|-------|-------|----------------|
| `MAX_ROOT_SET_SIZE` | 16 | Maximum members of an identity's root set; bounds the inception preimage and every root-signature group | §9.7.4.2 definitions |
| `MAX_NEXT_SET_SIZE` | 16 | Maximum members of an identity's next set; bounds the commitment list and every reveal group | §9.7.4.2 definitions |
| `MAX_RETAINED_SUFFIXES` | 8 | Maximum divergent suffixes a verifier retains per identity, and maximum slots a validating relay keeps per routing id. R9 states the admission and eviction rule; no other section restates it | §9.7.4.2 R9 |
| `MAX_KEY_EVENTS_PER_CHAIN` | 4096 | Maximum key events on one chain; a verifier rejects a chain that exceeds it. R8 makes every state-carrying event list every key the chain installed, so a chain's bytes grow with the square of this count. **The arithmetic, at 42 bytes per key-state entry** (a 32-byte public key, a one-byte condition discriminator, the eight-byte position a `Compromised{from: N}` entry carries, and a one-byte custody type): the event at sequence k carries about 42k bytes of entries, so the largest event on a full chain occupies about 172 KB and fits the 262,111-byte `value` bound of one frame (§9.10.12); the assembled chain totals about 352 MB, and a relay serves it as about 1,345 frames (§9.7.4.2 R9). One event MUST fit one frame, which is what 4096 respects; the assembled chain has no frame bound, because R9's write rule appends segments. A controller that rolls over on suspicion rather than on a schedule reaches neither figure | §9.7.4.2 R9 |
| `LEAF_REPLACEMENT_GRACE` | 86400s (24h) | How long after adopting a state-carrying event a peer waits for the identity to commit a replacement leaf before it proposes Remove for a leaf whose attestation fails the signature test. Set to §9.7.3's recommended 24-hour PCS Update interval, which is the cadence at which an identity replaces a leaf in an active context, so a peer waits exactly one such interval before acting on a leaf the identity has not replaced | §9.12 step 1a |
| `CONTENT_RESOLUTION_RETRY_WINDOW` | 300s (5 min) | How long a verifier holds a content signature whose `signing_key_id` it cannot resolve while its key-event-log resolution keeps failing, before rejecting. Set equal to `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7), the bound past which the same verifier already treats a key-event log as stale for this purpose | §9.7.1 |
| `MAX_PENDING_CONTENT_PER_SENDER` | 64 | Maximum content items a verifier holds per sender inside `CONTENT_RESOLUTION_RETRY_WINDOW`; beyond it the verifier drops the oldest, so a party sending content under fabricated `signing_key_id`s fills a bounded buffer | §9.7.1 |
| `MIN_WITNESSING_INTERVAL` | 300s (5 min) | Floor on the witnessing interval a key state may carry; R3 rejects a state-carrying event below it. A zero interval would make R10's self-observation an unbounded fetch loop | §9.7.4.2 R3, R10 |

### 9.18.B Configurable Parameters

The following constants have protocol-defined mechanisms and acceptable ranges, but the actual value is set by the context creator, relay operator, or deployer. Defaults are provided for when no explicit value is configured. Per ADR-043.

| Parameter | Default | Range | Mechanism | Spec Reference |
|-----------|---------|-------|-----------|----------------|
| Nesting depth | Unbounded (no protocol ceiling) | [1, u32 max] | `ContextParams::max_nesting_depth`. `None` = unbounded; contexts MAY set a limit. | §5.13.8 |
| Chain depth | 8 hops | [1, 255] (u8) | `ContextParams::max_chain_depth`. `None` = use default. No protocol hard max. | §24.4 |
| Session cap per caller | 1000 | [1, u32 max] | `ContextParams::session_cap`. `None` = use default. | §6.2.1 |
| Stream credit window | 32 chunks | [1, u32 max] | `ContextParams::stream_window_default`. Default per-stream credit headroom when `OutletStreamOpen` declares none. | §5.4.5 |
| Stream credit-stall timeout | 30s | [1, u32 max] | `ContextParams::stream_credit_stall_secs`. Seconds at zero credit before `SCP-OUTLET-6133` credit-stall cancel. | §5.4.5 |
| Stream cancel-ack timeout | 5s | [1, u32 max] | `ContextParams::stream_cancel_ack_secs`. Seconds after `OutletCancel` for the terminal chunk before `SCP-OUTLET-6135` forced closure. | §5.4.5 |
| Stream UCAN re-check cadence | 10s | [1, 60] | `ContextParams::stream_ucan_recheck_secs`. Receiver-side authoritative revocation re-check period for an active stream. | §5.4.5 |
| Concurrent inbound streams per invoker | 8 | [1, u32 max] | `ContextParams::max_concurrent_inbound_streams_per_invoker`. Per immediate-invoker admission ceiling. | §5.4.5 |
| Concurrent inbound streams per origin invoker | 16 | [1, u32 max] | `ContextParams::max_concurrent_inbound_streams_per_origin_invoker`. Operator-scoped per-origin-`iss` admission ceiling. | §5.4.5 |
| Concurrent inbound streams per outlet | 128 | [1, u32 max] | `ContextParams::max_concurrent_inbound_streams_per_outlet`. Per-outlet total fan-in admission ceiling. | §5.4.5 |
| Stream seal idle deadline | 45s | [1, u32 max] | `ContextParams::stream_seal_idle_secs`. Seconds the streaming-saga seal-phase pump may make no forward progress (no chunk forwarded to caller, no terminal chunk) before force-settle reclamation (`SCP-OUTLET-6134`). Distinct seam from `stream_credit_stall_secs` (outer forward path vs. inner credit). The **effective** deadline is clamped by construction: `max(configured, stream_credit_stall_secs + 1s)`, so credit-stall always fires strictly first and the terminal code is deterministic — no config-rejection rule or deployer obligation (§5.4.5). | §5.4.5 |
| Stream max duration | 900s (15 min) — **proposed default, product call** | [1, u32 max] | `ContextParams::stream_max_duration_secs`. Absolute wall-clock ceiling on the seal phase; force-settle reclamation (`SCP-OUTLET-6136`). The context default backing `OutletStreamOpen.timeout_ms == 0`; effective cap = `min(timeout_ms, stream_max_duration_secs * 1000)` (both compared in ms) when `timeout_ms != 0`. | §5.4.5 |
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
