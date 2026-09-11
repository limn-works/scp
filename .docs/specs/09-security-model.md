# 9. Security Model

## 9.1 Core Invariants

1. **Every action traces to a human.** No anonymous actors. No unaccountable software. A verifier tells a human-direct action from an agent-autonomous one by the identity that signed it: a human identity signs a human-direct action under its Active Signing Key (`#active`), and an agent signs an agent-autonomous action under the `#active` key of its own delegated identity, whose key-event log the human's log anchors by cooperative delegation (§9.7.4.2 definitions). A human identity's key state names one operational role, `#active`, and names no agent key. **The artifact that overturns the shared-DID `#agent` verification method of ADR-039 is the Track U2 revision of ADR-039 itself**, executing the row Alec confirmed on 2026-08-30; ADR-063, the inception-derived key-event-log identity substrate, states in its own Relates-to paragraph that the overturn sits downstream of it and out of its scope, and this spec cites ADR-063's sentence rather than the plan the row lives in. **The replacing model — how a delegator's log anchors a delegate's establishment events — is unspecified as of 2026-09-10** (`00-open-questions.md`), and §9.7.4.2 R3 rejects every chain that claims delegation until it lands. Every other section of this spec cites this paragraph for that model and does not restate it.
2. **Agents are context-bound.** No protocol-level cross-context awareness or communication for agents.
3. **Outlets are stateless and non-agentic.** They compute, they don't act.
4. **One agent per person per context.** No fleet multiplication within a space. A context admits at most one delegated agent identity per human identity. A delegated identity's key state names the delegator that anchors it (§9.7.4.2 definitions), so a verifier reads the human behind an agent from the agent's own chain. **How a controller produces that anchor and how a verifier checks it is unspecified as of 2026-09-10** (`00-open-questions.md`), and until it is specified a verifier rejects every chain that claims delegation (§9.7.4.2), so no delegated agent identity resolves and no agent signs an autonomous action.
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

SCP mandates one ciphersuite for v1, negotiates nothing, and falls back to nothing. Every identity key, every SCP envelope signature, every UCAN token signature, and every MLS leaf node credential uses ECDSA on NIST P-256 with SHA-256, FIPS 186-5. Alec ruled on 2026-09-10: "ok p256 then". P-256 is the curve every enclave, passkey provider, FIDO2 key, TPM, and browser WebCrypto speaks, so hardware custody becomes real on Apple platforms and in the browser.

Ed25519 was SCP's signature algorithm until 2026-09-10, when P-256 superseded it. No other sentence of this spec describes a live SCP key as an Ed25519 key or an X25519 key.

An SCP signature under the canonical hash construction of §9.5.1 is the 64-byte raw form: `r` then `s`, each a 32-byte big-endian integer at SEC1 fixed width, never DER. A second valid encoding would let a relay change a signature's bytes without holding the key.

Every signer MUST emit the low form, converting `(r, s)` to `(r, n − s)` whenever `s` exceeds half the group order, and every verifier MUST reject a signature whose `s` exceeds half the group order. The obligation binds a hardware signer too. A reveal-authorized event spends the standing commitment when it is composed, as the definitions of §9.7.4.2 state, so a signer that skipped normalization would spend a reveal on an event no verifier accepts.

A signer that runs in software MUST derive its per-signature nonce deterministically under RFC 6979 with SHA-256. That removes the nonce as a source of variation and as a source of private-key leakage under a weak random source.

A hardware signer draws its own nonce, so one message under one such key produces a different accepted signature on every call. This spec admits that signer because a key event is identified by its preimage digest and never by its bytes, which KERI's `spec-body` states under §SAID fields.

The low-`s` rule and the RFC 6979 rule bind every signature constructed under §9.5.1. They bind no MLS-layer signature and no JOSE ES256 signature on a UCAN an outside party issued. Neither RFC imposes a low-`s` rule and no widely deployed library normalizes, so a verifier applying the rule there would reject about half of every conforming peer's signatures.

**Point validation. The criterion: a verifier validates every P-256 point it reads from any wire before that point reaches any signature verification and any key agreement.** A verifier MUST reject a 33-byte point encoding whose leading byte is neither `0x02` nor `0x03`, MUST reject a 65-byte encoding whose leading byte is not `0x04`, MUST verify that the decoded point satisfies the P-256 curve equation, and MUST reject the point at infinity. A scalar multiplication under the standard formulas ignores the curve's `b` coefficient, so an HPKE decapsulation against a small-order point on an attacker-chosen curve leaks the recipient's long-term private scalar one crafted point at a time.

**Indicators, not the criterion.** The following name where a wire-read P-256 point arrives, and they do not bound the obligation above: the root set and the operational keys a key-state snapshot carries, the revealed keys of a reveal, the key a pre-rotation commitment covers when a reveal discloses it, the four keys of a KeyPackage attestation, the operator keys of the community relay list, the signer public key of a participation profile, and every HPKE encapsulated key and public key on every distribution path.

A P-256 signature-verification key is the 33-byte SEC1 compressed point. It is fixed length, so it carries no length prefix, and two encodings of one key would give two preimages for one logical structure.

An MLS signature public key is the 65-byte uncompressed SEC1 point, and an MLS-layer signature value is a DER-encoded `ECDSA-Sig-Value`, per RFC 9420 §5.1.2. Those encodings govern inside MLS, and the 64-byte raw form governs every signature this spec constructs.

The MLS ciphersuite is `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`, RFC 9420 ciphersuite 2.

Identity-to-identity encryption is HPKE under DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM, and RFC 9180 §7.1 fixes an HPKE public key and an encapsulated key at the 65-byte uncompressed SEC1 point. The HPKE suite matches the MLS ciphersuite so that the protocol carries the smallest cryptographic surface.

Key distribution for sender keys, access keys, and broadcast keys uses RFC 9180 Base mode under that same suite, and each of those three protocols supplies a distinct `info` string. An implementation MUST NOT supply an external nonce for the HPKE AEAD.

The Merkle tree hash is SHA-256 under the RFC 6962 construction: a leaf is `SHA-256(0x00 ‖ event_data)`, an interior node is `SHA-256(0x01 ‖ left ‖ right)`, and the empty tree's root is `SHA-256("")`. It governs the context event log. The key-event log of §9.7.4.2 is a hash chain and not a Merkle tree, so this construction does not reach it.

### 9.5.1 Canonical Hash Construction

The canonical hash construction is `SHA-256(domain_separator ‖ field_1 ‖ … ‖ field_N)`. The domain separator is UTF-8 and carries no length prefix. A variable-length field carries a 4-byte big-endian length prefix, a fixed-length field carries none, and an integer is big-endian at its declared width.

A repeated field is a 4-byte big-endian element count followed by each element under its own rule, in list order. The count is what makes two adjacent lists of fixed-length elements re-parse to one reading, because two adjacent 32-byte lists without it re-parsed under two readings and produced one identifier.

An absent optional field encodes as the 32 bytes `SHA-256(0x00)` under the same rule the present form takes: length-prefixed where the present form is variable-length, bare where the present form is fixed-length.

Changing any field's encoding, adding a field, or removing a field requires incrementing that separator's version suffix, and every signature made under the old separator becomes invalid. Four rules of the key-event log rest on that cost, and the definitions of §9.7.4.2 state each one: the key-algorithm discriminator travels beside every key from the first schema version, the key state carries no platform proof, the key state carries no relay endpoint, and the key-event seal ships with no live reader.

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
| 2 | `leaf_signature_key` | 65 bytes (uncompressed SEC1 P-256 public key in RFC 9420 §5.1.2's encoding — the MLS leaf `signature_key` being bound; the ECDSA key that self-signs the LeafNode, distinct from the three HPKE keys below) |
| 3 | `leaf_encryption_key` | 65 bytes (DHKEM(P-256) public key, RFC 9180 §7.1 — the LeafNode `encryption_key`, the **ratchet-tree** HPKE key that receives path secrets; RFC 9420 §7.2. Distinct from `init_key` below) |
| 4 | `init_key` | 65 bytes (DHKEM(P-256) public key, RFC 9180 §7.1 — the KeyPackage `init_key`, the HPKE key the Welcome's `EncryptedGroupSecrets` is sealed to at join; RFC 9420 §7.1. **`init_key != encryption_key`** on a KeyPackage — a distinct key, present only in the KeyPackage, single-use, consumed at join, never in the ratchet tree. Distinctness is a **KeyPackage-only** property: a bare LeafNode created without a KeyPackage — the group creator's leaf and every PCS-Update leaf (§9.7.1) — has exactly one HPKE key, its `encryption_key`, and no separate `init_key`; on such a leaf this field therefore carries `leaf_encryption_key`. The Add-time checks (§9.7.1 checks 7–8) do **not** apply to those leaves because they are **structurally** never admitted through an Add/Welcome — they enter via group creation or a Commit-borne Update — NOT because of that field-value equality. A verifier MUST NOT use `init_key == leaf_encryption_key` as a signal to skip the Add-time checks: those checks are gated by the handshake structure (every Add carries a KeyPackage `init_key`, RFC 9420 §7.1), never by an attestation field comparison (§9.7.1)) |
| 5 | `wrapping_key` | 65 bytes (DHKEM(P-256) public key, RFC 9180 §7.1 — the value of the `scp_wrapping_key` (`0xFF01`) LeafNode extension, the §9.16 per-sender-key wrapping HPKE key; distinct from both HPKE keys above) |
| 6 | `signing_key_id` | 4-byte BE length + UTF-8 bytes (`#active` — the verification method that signed this attestation) |
| 7 | `issued_at` | 8-byte BE u64 (Unix seconds; equals the leaf's `Lifetime.not_before`) |
| 8 | `expires_at` | 8-byte BE u64 (Unix seconds; equals the leaf's `Lifetime.not_after`) |

Note: the `KeyPackageAttestation` binds **all four** of the leaf's own public keys to the member's `did` (field 1), and is signed by the DID verification method named in `signing_key_id` (field 6, `#active` — never a root member). The attestation must vouch for the *whole* leaf, not a subset of its keys — each of the leaf's HPKE public keys is a distinct decryption capability, and any key left unbound is one an attacker who holds only the leaf **signing** key can substitute with a key of their own:

- **`leaf_signature_key`** (field 2, 65-byte uncompressed SEC1 P-256 point) — the ephemeral MLS leaf `signature_key` that self-signs the LeafNode.
- **`leaf_encryption_key`** (field 3, 65-byte DHKEM(P-256) public key) — the LeafNode **ratchet-tree** `encryption_key` (RFC 9420 §7.2), which receives HPKE-sealed path secrets on Commits. Binding it stops a stolen `signature_key` from being paired with an attacker-chosen ratchet-tree key that would let the attacker decrypt path secrets and read post-Add traffic.
- **`init_key`** (field 4, 65-byte DHKEM(P-256) public key) — the KeyPackage **`init_key`** (RFC 9420 §7.1), a key DISTINCT from `encryption_key`: the Welcome's `EncryptedGroupSecrets` is HPKE-sealed to the `init_key`, not the `encryption_key`. This is the **read-as-victim-at-join** vector, and the reason binding only `signature_key` + `encryption_key` is insufficient: a thief holding only the leaf signing key could craft a KeyPackage carrying the victim's `signature_key`, the victim's *public* `encryption_key` (passing that check), a genuine copied attestation — and an **attacker-chosen `init_key`**. The adder would then seal the Welcome to the attacker's `init_key`, and the attacker would decrypt the group secrets and read as the victim. Binding `init_key` closes this. Because the `init_key` lives ONLY in the KeyPackage (it is consumed at join and is NOT part of the ratchet tree), the verifier checks it **only at Add/Welcome time**, where the adder holds the full KeyPackage — see §9.7.1 (it is correctly not re-checked on later Commit/Proposal verification, because the read-as-victim attack lands at join).
- **`wrapping_key`** (field 5, 65-byte DHKEM(P-256) public key) — the value of the leaf's `scp_wrapping_key` (`0xFF01`) extension, the §9.16 per-sender-key wrapping HPKE key. Without binding it, a `signature_key` thief substitutes their own wrapping key and harvests other members' §9.16 sender keys distributed to the victim. Like `signature_key`/`encryption_key`, it is present on every leaf and is checked on both triggers — Add and Update (leaf introduction or change), not on a Commit that leaves the committer's leaf unchanged (§9.7.1 "Verification (MUST) — when it runs").

`encryption_key`, `init_key`, and `wrapping_key` are three **distinct** DHKEM(P-256) HPKE keys serving three distinct roles (ratchet-tree path secrets, Welcome seal, sender-key wrapping); the attestation binds each so none can be swapped for an attacker key. The attestation is deliberately **context-agnostic**: it carries no `context_id`. A KeyPackage is a per-identity, pre-published pre-key bundle that must be mintable offline — before any group it will be added to is known — so a context scope is unknowable at mint time; group-scope binding is provided separately and redundantly by the `scp_context_params` GroupContext extension (`0xFF02`, §5.13.3), which binds the leaf's actual group. The signature covers the §9.5.1 canonical hash of the eight fields above under the `"SCP-KEYPACKAGE-ATTESTATION-V1:"` domain separator. The attestation is carried in the MLS leaf as the `scp_keypackage_attestation` LeafNode extension (§9.18.7) and is re-issued on leaf-key rotation (§9.7.3). Verifiers resolve the `signing_key_id` verification method from the signer's **current** key state (§9.6.1) and check this signature; a leaf whose attestation does not verify — or whose `leaf_signature_key`, `leaf_encryption_key`, or `wrapping_key` does not match the leaf's actual keys, or whose `init_key` (at Add time) does not match the KeyPackage `init_key`, or whose `did` does not match the credential — MUST be rejected (fail-closed) per the §9.7.1 verifier rules. This structure is the direct analog of `IdentityLinkAttestation` (§3.5.2): a `#active`-signed statement binding an identity to an out-of-band fact, verified against the signer's current key state.

**`scp_keypackage_attestation` (`0xFF03`) LeafNode extension body.** The extension body is a **deterministic length-prefixed binary serialization** — explicitly NOT MessagePack or JCS — chosen so that all four bindings (native, wasm, UniFFI, NAPI) produce byte-identical extension bytes. It is the eight attestation fields, **in the same order as the signed preimage above**, followed by the raw 64-byte P-256 signature (§9.5):

```
BE32(len(did)) || did
  || leaf_signature_key                       (65 raw bytes, no length prefix)
  || leaf_encryption_key                      (65 raw bytes, no length prefix)
  || init_key                                 (65 raw bytes, no length prefix)
  || wrapping_key                             (65 raw bytes, no length prefix)
  || BE32(len(signing_key_id)) || signing_key_id
  || issued_at                                (8-byte BE u64)
  || expires_at                               (8-byte BE u64)
  || signature                                (64 raw bytes)
```

The variable-length fields (`did`, `signing_key_id`) carry a 4-byte big-endian length prefix; `leaf_signature_key` is the 65-byte uncompressed SEC1 P-256 public key RFC 9420 §5.1.2 defines, and `leaf_encryption_key`, `init_key`, and `wrapping_key` are each a 65-byte DHKEM(P-256) public key (all fixed-length, no length prefix); `issued_at`/`expires_at` are 8-byte big-endian unsigned integers; the trailing 64 bytes are the raw `r || s` P-256 signature (§9.5) over the §9.5.1 canonical hash (the domain separator appears only in the signed preimage, never in the extension body). This mirrors how the `scp_wrapping_key` (`0xFF01`) LeafNode extension carries its raw HPKE public key. A byte-exact known-answer vector is in §25.23 (Vector 37).

**ParticipationProfile** — domain: `"SCP-PARTICIPATION-PROFILE-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `subject_did` | 4-byte BE length + UTF-8 bytes |
| 2 | `signer_public_key` | 33 bytes — the SEC1 compressed P-256 point (§9.5) |
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
| 4 | `wrapping_pubkey` | 65 bytes (DHKEM(P-256) public key, RFC 9180 §7.1) |
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

Note: The P-256 ECDSA signature is over `SHA-256("SCP-VOTE-V1:" || fields)`. The `proposal_id` binds the vote to a specific proposal, preventing cross-proposal replay. `VoteType` is serialized as compact JSON (equivalent to `json.dumps(separators=(',', ':'))` in Python).

**KeyDestructionAttestation** — domain: `"SCP-KEY-DESTRUCTION-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 2 | `member_did` | 4-byte BE length + UTF-8 bytes |
| 3 | `destroyed_at` | 8-byte BE u64 |
| 4 | `key_state_head` | 32 bytes, no length prefix; §9.7.1's log-anchored row constructs the value and this cell restates none of it. First-seen is the sole acceptance condition against a key the state lists `Compromised` (§9.7.1) |
| 5 | `method` | 1-byte U8 discriminator (0x00=SoftwareOnly, 0x01=HardwareBacked) |
| 6 | `platform_attestation` | 4-byte BE length + raw platform bytes if present; absent = `00 00 00 20` followed by the 32 bytes `SHA-256(0x00)` |

Note: the preimage binds `key_state_head`, which is what makes this structure the log-anchored evidence class of §9.7.1 rather than the attestation class. A verifier that read an unsigned `key_state_head` would take the anchoring position from the signer, so the field is inside the signed preimage. §9.15 states the structure's field semantics and the limit the class carries for a key the state lists retired with a compromise position.

**ScpCustodyViolationAttestation** — domain: `"SCP-CUSTODY-VIOLATION-V1:"`

ADR-039, shared-DID human-agent identity model, defines a custody violation at enforcement-stack layer 4 as a permanent record that one verifier writes about a subject who never consented to it. A reader must be able to establish which verifier wrote a given record, and must be able to detect a record that any other party altered after that verifier signed it. Fields 1 through 7 below feed one P-256 ECDSA signature that carries both properties.

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `subject_did` | 4-byte BE length + UTF-8 bytes |
| 2 | `timestamp` | 8-byte BE u64 |
| 3 | `violation_tag` | 1-byte U8 discriminator (`0x00` = `CategoryAViolation`, `0x01` = `AttestationMismatch`) |
| 4 | `violation_field_1` | 4-byte BE length + bytes — `action` (UTF-8) when `violation_tag` is `0x00`, `claimed_custody` (UTF-8) when `violation_tag` is `0x01` |
| 5 | `violation_field_2` | 4-byte BE length + bytes — `signer_key_id` (UTF-8, whichever verification method the shipped `SigningKeyId` type names) when `violation_tag` is `0x00`, `observed_behavior` (UTF-8) when `violation_tag` is `0x01` |
| 6 | `violation_field_3` | 4-byte BE length + raw bytes — `signature_evidence` when `violation_tag` is `0x00`, `attestation_evidence` when `violation_tag` is `0x01` |
| 7 | `verifier_did` | 4-byte BE length + UTF-8 bytes |

Note: `verifier_signature` is one field this preimage omits, and it is the only such field, so a party who alters `subject_did`, `timestamp`, any component of `violation`, or `verifier_did` moves this hash away from whatever value a stored `verifier_signature` covers, and a verifier then rejects that altered record. `violation_tag` at position 3 separates both variants: without `violation_tag`, a `CategoryAViolation` whose three variable-length fields carry the same bytes as an `AttestationMismatch` hashes identically, so a verifier's signature over one variant transfers to another. A verifier resolves `verifier_did` to that identity's `#active` verification method and checks `verifier_signature` against `SHA-256("SCP-CUSTODY-VIOLATION-V1:" || fields)`. `verifier_signature` establishes who wrote a record. It does not establish that a recorded violation occurred, because that verifier alone chose what to write. A `CounterAttestation` carries this same 32-byte hash in its `violation_reference` field, specified below. **No test vector pins this preimage**: §25.25 records that Vectors 39 and 40 were deleted on 2026-09-10 rather than carried onto P-256, because the plan's §1 table marks both constructs CUT and Track U4 owns the teardown.

**`signer_key_id` names a verification method the identity model superseded.** The shipped `SigningKeyId` type renders `"#active"` and `"#agent"`, and §9.7.4.2 gives a human identity no `#agent` verification method, because an agent holds its own key-event log and its own `#active`. No section states which key a `CategoryAViolation` names once the offending signature comes from a delegated agent identity, and this section decides nothing about it.

**CounterAttestation** — domain: `"SCP-COUNTER-ATTESTATION-V1:"`

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `subject_did` | 4-byte BE length + UTF-8 bytes |
| 2 | `violation_reference` | 32 bytes (fixed-size, no length prefix) — derivation stated below |
| 3 | `explanation` | 4-byte BE length + UTF-8 bytes |
| 4 | `timestamp` | 8-byte BE u64 |

**`violation_reference` derivation (normative).** `violation_reference` MUST equal a `ScpCustodyViolationAttestation` signing hash, defined immediately above, computed over whichever record this counter-claim contests: `SHA-256("SCP-CUSTODY-VIOLATION-V1:" || fields 1..7)`. Any other 32-byte value names no record.

A verifier that holds both records MUST reject a counter-attestation when either check fails:

1. `counter.violation_reference != SHA-256("SCP-CUSTODY-VIOLATION-V1:" || violation fields 1..7)`.
2. `counter.subject_did != violation.subject_did`.

Check 1 gives two independent verifiers one answer to "does this counter-claim answer this violation record", which a free-form identifier could not give. Check 2 stops one subject from contesting a record naming a different subject.

This derivation omits a violation record's `verifier_signature`, and that omission is deliberate. A verifier who signs one record's identical facts under a rotated key produces that identical reference, so a counter-claim a subject already published keeps pointing at that record instead of becoming orphaned. Two verifiers who record different facts — different `timestamp`, different `action`, different evidence bytes — produce different references, because fields 1 through 7 cover every recorded fact. This specification rejected one alternative, hashing a serialized record that includes `verifier_signature`: such a value separates two records only when one verifier signs identical facts under two keys, which is one claim, not two, and it would require a third domain separator plus a record serialization §9.5.1 does not define.

An author computes `violation_reference` from a violation record it holds. An author that holds no violation record has nothing to contest and MUST NOT publish a counter-attestation.

Note: ADR-039 assigns a counter-attestation signature to `#active` rather than `#agent`, so that publishing a counter-attestation demonstrates human involvement. A human identity carries no `#agent` verification method after 2026-09-10, because an agent is a separate delegated identity holding its own `#active` (§9.7.4.2), so a verifier reads that assignment as naming the subject identity's own `#active`. This preimage carries no `signing_key_id` field, because a party that names its own fragment inside a record it also signs can name one key while signing with another. A verifier instead resolves `#active` from the key state the subject's latest state-carrying key event carries (§9.7.4.2 R8) and checks `signature` against that key alone; the DID document this sentence once named does not exist, because ADR-063, the inception-derived key-event-log identity substrate, replaced it with the key-event log and the service record. A signature that a delegated agent identity produced then fails, which enforces ADR-039's assignment. A verifier that resolves a delegated agent identity's `#active` establishes agent authorization and establishes nothing about human involvement. **No test vector pins this preimage either**, for the reason §25.25 records.

**UCAN signing:** ES256 — ECDSA on P-256 with SHA-256, the JOSE algorithm identifier the UCAN specification takes for this curve. The nonce field (`nnc`) is mandatory and must be unique per token issuance. This prevents UCAN token replay. UCAN token expiry (`exp`) MUST NOT exceed 24 hours (matching the nonce deduplication cache window in §9.8.2). Tokens with longer expiry could be replayed after nonce cache eviction. **UCAN revocation** is per-context via `RevocationList` — an append-only map of token CIDs to revocation states (Active, RevocationPending, Revoked). Revocations are distributed as MLS application messages to all context members. Revocation check is step 10 of the 11-step validation pipeline (ADR-016) and is performed on every capability exercise. The system is **fail-closed**: tokens in `RevocationPending` state (revocation initiated but not yet confirmed via MLS) are denied. See ADR-016 criterion 7 and `scp-core/crypto/ucan/revoke.rs` for the full specification.

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

1. The client queries every relay it knows for the record at the identifier's routing ID: the relays the identity's service record names (`03-identity.md` §3.10.13), and the community relays of the fallback set (definitions; `18-addressability-and-deployment.md` §18.5.1). A client that holds no accepted baseline for the identifier applies R11's first-contact floor (§9.7.4.2 R11).
2. The client recomputes the identifier from the served chain's inception event and rejects a chain whose recomputed identifier differs from the identifier it is resolving (§9.7.4.2 R2).
3. The client verifies every event of that chain under §9.7.4.2 R3 — each indexed signature against the key at its index, each reveal against the standing commitment — and settles two chains that diverge by the fork-precedence rule (§9.7.4.2 R6).
4. The client derives the key state from the latest state-carrying event of the chain it adopted (§9.7.4.2 R8). Resolution yields key state and nothing else; the identity's transport and service metadata rides in a separate service record the client resolves on its own terms (`03-identity.md` §3.10.13), and no DID document is an output of this procedure — ADR-063 defers the `did:scp` facade and builds none.

The client reads no key from the frame that carried the record (§9.10.12). No trusted third party is required, and no key needs to be known before the resolution starts: the identifier and the inception event are the whole trust root.

**The record carries no signature of its own** (§9.10.12 states the frame's bytes and why it carries none), so nothing authenticates the frame beside the chain inside it. A relay's write decision is chain verification under §9.7.4.2 R2 and R3 plus the slot rule of §9.7.4.2 R9 (`03-identity.md` §3.10.2 states the procedure), and a resolver's trust decision reads the log under steps 2 through 4 above.

**MITM on resolution is impossible given the correct identifier.** A relay cannot serve a fraudulent chain under an identifier it does not control, because step 2 recomputes the identifier from the inception event the chain carries and a different inception event yields a different identifier. Tampering is detectable without trusting any intermediary.

**Stale record prevention:** the frame carries no sequence number, and a relay appends a frame's events to the chain it holds and replaces none of them (§9.7.4.2 R9; `03-identity.md` §3.10.2 states the procedure). The client discards, without changing its accepted state, a candidate whose chain is a head of the accepted chain at a sequence strictly lower than the highest it has accepted (§9.7.4.2 R12). Two key-event chains that diverge from a shared prefix are not comparable by sequence, and a client settles them by the fork-precedence rule of §9.7.4.2 R6, which may adopt a chain whose head sequence is lower than the head the client previously held (§9.7.4.2 R12).

**The remaining question:** "Is this the right identifier?" The identifier↔inception binding proves that a chain belongs to an identifier, but cannot prove the binding between an identifier and a person. This is an out-of-band verification problem addressed by Key Continuity Verification (§9.11).

**No relay is trusted.** The log authenticates the record under §9.7.4.2 R2 and R3, so a resolver's integrity guarantee never rests on which relay served the record. Freshness at first contact comes from the two distinctly-operated relays R11 requires, and afterwards from the accepted baseline R12 holds against a candidate. How the party came to hold that baseline is a record the SDK keeps and no rule reads (§9.7.4.2 definitions).

### 9.6.3 Relay List Authentication

An identity's relay list rides in its **service record**, the second owner-signed resolvable that `03-identity.md` §3.10.13 defines and owns. This section states how a client authenticates that list; §3.10.13 states what else the record carries, who signs it, and how a resolver settles two copies.

**For an inception-derived identifier:** the client verifies the service record's signature against the operational key the identity's latest state-carrying key event designates for the service-record role (§9.7.4.2 definitions), and it verifies that key event under §9.7.4.2 R2 and R3 before it reads the designation. Two verifications chain: the log authenticates the designated key, and the designated key authenticates the relay list. Substituting a relay list therefore requires the designated key, and substituting the designation requires a threshold of the identity's standing root. The key-event log itself carries no relay list.

**For transport adapters with native relay lists:** Some transport adapters (e.g., Nostr via NIP-65) publish relay lists in transport-specific formats signed by a keypair derived from the identity's key material. This provides relay list authentication independent of the identity method but is adapter-specific, not a protocol requirement.

**Attack: relay list substitution.** A compromised relay could serve a stale service record, directing messages to relays the recipient no longer uses. Defense: a client takes the relay list from the highest-sequence service record whose signature verifies against the designated key, and it rejects a record at a sequence lower than the highest it has already accepted for that identity (§3.10.13). A relay that holds the designated key's signature over no newer record cannot manufacture one.

### 9.6.4 First-Contact Trust Bootstrapping

**This section is the one home of the first-encounter rule, and it assigns the standing that §9.11 then reads.** A party meeting an identifier for the first time resolves it under §9.7.4.2, which states how that party obtains the chain, recomputes the identifier under R2, derives the key state under R8, and reaches one of the six verdicts R14 defines. This section reads that verdict and nothing else, and it carries its own standing check rather than citing the gate list of §9.11, because a verifier that recorded `Verified` on a verdict under which it adopted no chain would fix a standing against a chain it never adopted, after which the key-change trigger of §9.11 could never fire for that identifier.

**First contact assigns three standings.** A verdict of `Confirmed` or `Adopted` sets `Verified` and records the adopted chain's root-install digest. A verdict of `Contested` sets `PendingReverify` and records no digest. A verdict of `Inconclusive{cause}` sets `Unresolved` and records no digest. A verdict of `Invalid{at_event}` sets `PendingReverify` and records no digest, because that verdict rests on an author-attributable defect only that identifier's own signer could have written, so something suspect about the identifier is exactly what the verifier learned. A first contact returns no `Discarded{accepted_head}`, which R12 defines over an accepted head a first contact does not hold.

A first contact applies trust-on-first-use to the chain as the resolver resolved it, whatever that chain contains. A `RootRecovery` already on the chain at first contact is part of the history the resolver is trusting on first use, and the resolver is not observing one.

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

**KeyPackage leaf key and DID attestation.** Per RFC 9420 §5.3, the `signature_key` in a KeyPackage's `leaf_node` field signs the leaf node itself. In SCP this is an **ephemeral, context-scoped P-256 key** generated by the MLS layer (`SignatureKeyPair::new()`) — it is NOT a DID verification method, and a verifier MUST NOT expect it to resolve to one. The leaf is self-signed by this ephemeral key, exactly as RFC 9420 requires. Per-message sender identity is carried separately, by the inner-envelope `#active` signature (§9.8.1), never by the MLS leaf key.

Binding the ephemeral leaf key to a DID is the job of a separate **KeyPackage attestation**: a signed statement, produced by the identity's Active Signing Key (`#active`), that binds `{ DID, leaf signature_key, leaf encryption_key, init_key, wrapping_key, signing_key_id, issued_at, expires_at }` (binding **all** of the leaf's public keys — the P-256 `signature_key`, and the three distinct DHKEM(P-256) HPKE keys: the LeafNode ratchet-tree `encryption_key`, the KeyPackage `init_key` (`init_key != encryption_key`; the Welcome is HPKE-sealed to `init_key`), and the `scp_wrapping_key` `0xFF01` `wrapping_key` — see §9.5.2 for why each is required). An attestation is minted at **every leaf-creation site — all three of them**: (1) group creation (`create_group`, where the creator's leaf is built directly with **no** published KeyPackage — the creator leaf still has a LeafNode `Lifetime`, just no `KeyPackage` wrapper), (2) add-time KeyPackage generation (the published pre-key bundle), and (3) every PCS Update, which generates a fresh ephemeral leaf key and therefore requires a fresh attestation over it (§9.7.3). In each case `issued_at`/`expires_at` are set to the leaf's own `Lifetime.not_before`/`Lifetime.not_after`, so the attestation's validity window is exactly the leaf's lifetime (this generalizes across all three sites — the creator leaf has a `Lifetime` but no `KeyPackage.Lifetime`). The `signature_key`, `encryption_key`, and `wrapping_key` bindings are present at **all three** sites (every leaf carries the `scp_wrapping_key` `0xFF01` extension and a ratchet-tree `encryption_key`). The `init_key` binding, however, is meaningful only at site (2): only a published KeyPackage has a distinct `init_key`, and only a KeyPackage leaf is admitted through an init-key-sealed Welcome. At sites (1) and (3) the leaf has no KeyPackage — its sole HPKE key is its `encryption_key` — so the attestation's `init_key` field simply carries `leaf_encryption_key` there. Verifiers never run the Add-time `init_key` checks (§9.7.1 checks 7–8) against those leaves **because such leaves are structurally never admitted through an Add/Welcome** — they enter via group creation or a Commit-borne Update — NOT because of that field-value equality; a verifier MUST NOT treat `init_key == leaf_encryption_key` as a license to skip the Add-time checks (see the Verification structural note). Its preimage follows the §9.5.1 canonical construction under the domain separator `"SCP-KEYPACKAGE-ATTESTATION-V1:"` (structure in §9.5.2). The attestation rides **in the leaf node as an MLS LeafNode extension** (`scp_keypackage_attestation`, extension type `0xFF03`, §9.18.7), mirroring the existing `scp_wrapping_key` LeafNode extension — so it is carried in the ratchet tree, is available to any verifier that reads the leaf, and is covered by the leaf's self-signature. Placing it in the leaf (rather than as a `Credential` field) is deliberate: a LeafNode extension travels with the leaf through Welcome and Commits, is committed by the leaf signature, and needs no separate distribution channel. A root member is NOT used — the root is reserved for establishment events (§9.7.4.2 definitions define the term: every key event, and only key events) and after inception never fixes a commitment alone (§9.7.4.2 R1); attestation issuance is an operational action, not an establishment event. Signing uses the identity custody `KeyCustody::sign` — a single async signature, with no raw key export, so it is compatible with hardware custody and needs no `openmls` change.

**Verification (MUST) — when it runs.** Attestation verification is triggered by **leaf introduction or change**, never by mere message arrival. A member verifies a leaf's KeyPackage attestation when — and only when — that leaf **enters or is replaced in** the group: (a) at an **Add**, the KeyPackage introducing a new member's leaf, and (b) at an **Update / Commit-with-UpdatePath**, an existing member replacing their own leaf with a fresh ephemeral key (§9.7.3). A **Commit or Proposal that does not introduce or change the committer's leaf carries no new attestation to check** — the leaf and its embedded attestation are byte-for-byte the ones already fully verified when that leaf was introduced — so the verifier **MUST NOT** re-run attestation verification, and in particular **MUST NOT** re-resolve the committer's DID, for it. Skipping it is safe (there is nothing to re-check — the attestation is unchanged and was already fully verified) and is also necessary: gating every steady-state Commit on a fresh DID resolution would let an attacker who degrades one member's DID resolution — a network partition between that member's relays and the group — get that member's Commits rejected group-wide, forking the epoch or censoring the member. The trigger is therefore leaf-change, not message-arrival.

**Verification (MUST) — the checks.** On each triggering event (an Add or an Update) the verifier MUST resolve — from the attesting identity's **current** key state (§9.6.1) — the key its `signing_key_id` role names, verify the KeyPackage attestation against it, and confirm ALL of the following. Checks 1–6 and 9–13 apply on **both** triggers (Add and Update); checks 7 and 8 — the two `init_key` checks — apply at **Add/Welcome time only** (an Update replaces a ratchet-tree leaf, which has no `init_key`). The two resolution-dependent checks — 1 and 2 — additionally carry an **Add-vs-Update failure policy** stated in each: a new member's **Add** is fail-closed on resolution failure, while an already-admitted member's **Update** falls to a bounded last-known-good grace on a transient resolution *failure* (but never on a resolution *success* that returns a rotated key); see the **Resolution failure policy** below. **The Add-time checks (7–8) are triggered by the handshake structure, NOT by any attestation field value.** A verifier MUST NOT decide whether to run checks 7–8 by comparing the attestation's `init_key` to its `leaf_encryption_key`: the Add-time checks run against **every** Add proposal — which, by RFC 9420 §7.1, always carries a KeyPackage bearing an `init_key` — and against no other message. The creator / PCS-Update carve-out (§9.5.2 field 4) is **structural**, not a field-value test: creator and Update leaves are admitted through group creation or a Commit-borne Update — **never** through an Add/Welcome — so checks 7–8 simply never run against them. Keying the carve-out on `init_key == leaf_encryption_key` would be a defect: a signing-key-only attacker could harvest a victim's genuine creator/Update attestation (whose `init_key` field legitimately equals `leaf_encryption_key`) and re-present it inside an Add carrying the attacker's own `KeyPackage.init_key`, and a verifier that skipped check 7 on the field-value match would reopen the read-as-victim vector.

1. the `signing_key_id` names the role the identity's key state lists `#active` and `current`, and resolution binds to **that current key only** — a verifier MUST NOT accept an attestation signed by a key the resolved current key state lists in any of the three conditions of §9.7.1 that are not `current`, nor by any key that key state does not list `current` in the `#active` role. (Without this, an attestation signed by a rotated-away key would still verify, and the revocation-by-rotation of §9.12 would not bite.) This current-key binding is enforced on **both** triggers, but the resolution-failure policy differs by trigger. On an **Add** it is **fail-closed** — a resolution failure rejects the join (check 2; **Resolution failure policy** below). On an already-admitted member's **Update** the success-vs-failure distinction is load-bearing: a resolution **success** that returns a **rotated-away key** (the current key state no longer lists the attesting `#active` `current`) still fails this check and the Update is **rejected** — rotation revokes exactly as on an Add — whereas a transient resolution **failure** does not hard-reject but falls to the bounded last-known-good grace of the **Resolution failure policy** below, so a key-state resolution outage cannot fork the epoch or censor an existing member. On an already-admitted member's Update the verifier re-resolves with its cache bypassed before it rejects on this check (**Resolution failure policy** below states that obligation once);
2. **current-key resolution freshness:** the key state used to satisfy check 1, derived from the identity's key-event log (§9.7.4.2 R8), MUST be no older than `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7 — 300s / 5 minutes, tied to the §9.14 clock-skew tolerance). A resolver-cache entry older than this bound MUST NOT be used for the current-key check — it MUST trigger a **fresh** resolution (on an **Add**, a resolution failure then rejects, per the **Resolution failure policy** below; on an already-admitted member's **Update**, a transient resolution failure instead falls to the bounded last-known-good grace defined there, while a resolution *success* returning a rotated key still rejects). The ≤ 5-minute freshness guarantee presupposes **rollback-resistant DID resolution** — see the **Rollback-resistance assumption** below. The §9.18.7 registry row for that constant states its relation to the §9.10.7 privacy cache TTL, and no other sentence in this spec restates it. This hard-bounds revocation latency — a retired `#active` cannot keep verifying attestations past rotation for longer than this bound (§9.12), regardless of how long the privacy cache would otherwise retain the pre-rotation document;
3. the attestation's P-256 signature verifies against that resolved current verification method (over the §9.5.1 canonical hash under `"SCP-KEYPACKAGE-ATTESTATION-V1:"`). On an already-admitted member's Update the verifier re-resolves with its cache bypassed before it rejects on this check (**Resolution failure policy** below states that obligation once);
4. the attestation's `leaf_signature_key` equals the leaf's actual `signature_key`;
5. the attestation's `leaf_encryption_key` equals the leaf's actual LeafNode `encryption_key` (the DHKEM(P-256) ratchet-tree HPKE key, RFC 9420 §7.2) — so a stolen `signature_key` cannot be paired with an attacker-chosen ratchet-tree key to decrypt path secrets (§9.5.2). **This binding — not check 8 — is what denies the read-as-victim-at-join closure:** forcing `leaf_encryption_key` to the victim's real key means a signing-key-only attacker cannot substitute a decryption key it controls, and (with check 7 forcing the KeyPackage's `init_key` to the attested value, which for a copied bare-leaf attestation is that same `leaf_encryption_key`) the Welcome's group secrets remain sealed toward a key only the victim can decrypt. Check 8 is the RFC 9420 §10.1 malformed-KeyPackage guard, not this closure;
6. the attestation's `wrapping_key` equals the value of the leaf's `scp_wrapping_key` (`0xFF01`) LeafNode extension — so a stolen `signature_key` cannot be paired with an attacker-chosen sender-key wrapping key to harvest other members' §9.16 sender keys (§9.5.2);
7. **`init_key` binding (Add/Welcome time only):** when processing an Add/join, the attestation's `init_key` equals the **KeyPackage's** `init_key` (the DHKEM(P-256) HPKE key the Welcome's `EncryptedGroupSecrets` is sealed to, RFC 9420 §7.1) — so a thief holding only the leaf `signature_key` cannot craft a KeyPackage that reuses the victim's `signature_key` + public `encryption_key` + copied attestation but substitutes an **attacker-chosen `init_key`**, which would seal the Welcome to the attacker and let it read as the victim. **Critical asymmetry:** `init_key` lives ONLY in the KeyPackage — it is consumed at join and is NOT part of the ratchet tree — so it can be checked ONLY at Add/Welcome time, where the adder holds the full KeyPackage. It is correctly **not** re-checked on later Commit/Proposal verification (there is no `init_key` on a ratchet-tree leaf to check against, and the read-as-victim attack lands at join, not on a later Commit). This check runs on every Add regardless of whether `init_key` happens to equal `leaf_encryption_key` (see the structural note above);
8. **`init_key != encryption_key` (Add/Welcome time only) — the RFC 9420 §10.1 malformed-KeyPackage / HPKE-key-reuse guard (defense-in-depth):** reject any Add whose KeyPackage has `init_key == encryption_key`. RFC 9420 §10.1 requires a KeyPackage's `init_key` and its LeafNode `encryption_key` to be **distinct**; a KeyPackage that reuses one key for both roles is malformed and MUST be rejected. SCP names this as an **explicit** verifier MUST — defense-in-depth — rather than depending silently on the MLS library enforcing §10.1. **This check does NOT, on its own, close the read-as-victim-at-join vector:** that closure comes from binding the decryption keys (check 5, in concert with check 7), which forces the Welcome's group secrets to seal toward the victim's key. Check 8 is the belt-and-suspenders §10.1 hygiene guard on the KeyPackage's own two HPKE keys; it additionally rejects the degenerate `init_key == encryption_key` KeyPackage a signing-key-only attacker would reach for when re-presenting a victim's copied bare-leaf attestation (whose `init_key` field equals `leaf_encryption_key`, because that leaf had no KeyPackage) inside an Add;
9. the attestation's `did` equals the DID carried in the leaf's `ScpCredential`;
10. the attestation's `signing_key_id` equals the `signing_key_id` carried in the leaf's `ScpCredential` — the credential and the attestation MUST name the **same** verification method (explicit equality, so a leaf cannot claim a credential under one key while attesting under another);
11. the attestation's `expires_at` equals the leaf's `Lifetime.not_after` **and** its `issued_at` equals the leaf's `Lifetime.not_before` — the attestation's validity window is exactly the leaf's own lifetime, not a wider self-asserted one;
12. **lifetime cap:** `expires_at - issued_at <= MAX_KEYPACKAGE_ATTESTATION_LIFETIME` (§9.18.7) — reject any attestation whose self-asserted validity window exceeds the protocol maximum, so a compromised leaf key cannot be reused indefinitely (§9.7.3, §9.12);
13. **freshness:** `issued_at < expires_at` (reject any attestation with `expires_at <= issued_at`), the attestation is unexpired at the verifier's current time, and `issued_at` is not dated further into the future than the §9.14 clock-skew tolerance (5 minutes).

It is the **attestation** that is verified against the resolved key state — never the leaf signature itself. **Fail-closed scope (positive whitelist).** Attestation verification is MANDATORY and fail-closed for **all DIDs**: a leaf whose attestation is absent, malformed, expired, or failing any check above MUST be rejected. This applies to every identity without exception, and enforcement MUST NOT be keyed on any prefix of an identifier's textual form. The **only** exemption is a narrow testing carve-out, **gated behind the `testing` feature so it is never present in shipped production artifacts**, and it keys on the test construct rather than on any identifier's textual form: an identity the `testing` feature created, whose key-event log the SDK holds locally, skips relay resolution and skips §9.7.4.2 R11's two-relay first-contact rule. The verifier still runs every check above against the locally held log, and the carve-out relaxes nothing else. No identity a shipped artifact resolves is exempt.

**Resolution failure policy — Add is fail-closed; an already-admitted member's Update gets a bounded last-known-good grace.** When the verifier cannot resolve the signer's key-event log — every relay it reached timed out, a verifier holding no accepted baseline for the signer fell below R11's first-contact floor, or any other resolution error — the policy depends on whether the leaf's DID is a **new member** (Add) or an **already-admitted member** (Update / their own leaf-changing Commit), because the availability trade-off is opposite in the two cases. In **both** cases a resolution *success* takes precedence: a key state that resolves and shows the attesting `#active` **rotated away** fails check 1 and rejects — the grace below is for resolution *failure* only, never for a successful resolution that returns a new key. R11's floor binds a first contact only, so a verifier that already tracks the signer's chain resolves against one relay and a single relay's outage is not a resolution failure for it.

- **New member (Add) — fail-closed, no stale fallback.** A resolution failure on an Add is a **REJECT** (fail-closed), never accept-if-uncertain, and the verifier **MUST NOT fall back to a stale or pre-rotation cached key state**. Falling back would open a **rotation-bypass**: an attacker who can *induce* resolution failures (intermittently disrupting the reachability of the identity's relays) could pin verifiers onto a **pre-rotation** cached key state in which the retired `#active` still resolves, so old attestations continue to verify past a rotation — up to the cache TTL — defeating the revocation-by-rotation lever of §9.12. This is the cross-group **Add** path — the actual leaf-reuse threat (§9.7.3 "Scope of the PCS bound") — so it keeps the tight, fail-closed current-key bound of check 2. Delaying a not-yet-member forks and censors nothing, so the correct availability posture is to **retry/queue the join**, not to admit on a possibly-retired key. The resolver cache is retained **only as a positive same-or-fresher optimization** for this current-key check, never as a fallback *for* a failed resolution, with a freshness TTL no longer than the bound check 2 names.
- **Already-admitted member (Update) — bounded last-known-good grace on transient failure.** An existing member replacing their own leaf is a different posture: they already passed fail-closed verification at their own Add, and their Commits carry the group forward. Here, on a transient resolution **failure** (the log cannot be fetched at all), the verifier uses the member's **last-known-good** key state — the most recent one it successfully resolved — within a **bounded grace** (bounded by that key state's own retention, §9.10.7, and always overridden by the next successful resolution) **instead of** hard-rejecting, so a transient resolution outage cannot fork the epoch or censor an existing member (the BLACK-C22-10 liveness/censorship vector). **Only an `Adopted` verdict refreshes the staleness clock check 2 reads.** A `Confirmed` verdict refreshes the verifier's liveness evidence and nothing else, so a verifier whose accepted head has not advanced within `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7) is in this failure branch however many times a relay confirmed its baseline. Without that scoping an attacker holding a phished `#active` re-points the identity's service record at its own relays, the victim's post-rotation publish reaches nobody, and every peer resolving the byte-identical pre-rotation head is served `Confirmed` and treats the retired key as `current` indefinitely; a rule that fired only on strictly-lower sequences would not reach that equal-sequence attack at all. **Before rejecting an already-admitted member's Update on check 1 or check 3, the verifier MUST re-resolve that identifier's key-event log with its cache bypassed, and rejects only when the fresh resolution still fails the check.** The case that obligation closes is a resolution success against a cache-fresh pre-rotation key state: the member rotates `#active` and issues the §9.12 step-2 Update in the same minute, a peer holds a pre-rotation key state four minutes old, check 2 admits that entry because it is inside the bound, and check 3 then verifies the member's new-key signature against the retired key and fails. A resolution success reaches no grace, so without the re-resolution every planned rotation — including the custody migration of `03-identity.md` §3.2.1 case 1, which is not a compromise — forks the epoch at every peer whose cached key state is younger than the bound and fresher than the rotation. The content path carries the same obligation under **A content-signature freshness bound** below. The grace does not weaken revocation, either: revoking an already-admitted, genuinely-compromised member is a **governance Remove** (as in MLS — the standard mechanism for evicting a compromised member), not a per-commit hard reject driven by an induced resolution outage. This presupposes a **governance authority other than the compromised member**. In a **SingleAdmin** context (§5.9) where the sole admin's full MLS state is compromised, no other party can issue the Remove; that case is a **context-re-creation** event (§5.9 governance / §5.11A migration), not a grace-recoverable one — compromise of the sole governance authority is game-over for the context regardless of this mechanism.

**Standing gates the identity layer, never MLS processing.** Every member processes a handshake message from an existing member identically, whatever that member's `ContinuityStanding`, because a member that held one member's Commit would fork the epoch: under RFC 9420 §12.4 almost every Commit carries an UpdatePath, and a member that does not apply it holds different key material from every member that did. The standing acts one layer up. Where the authoring member's standing is `Contested`, `PendingReverify`, or `Unresolved`, the verifier records the replaced leaf's attestation as **unverified**, grants that member nothing — no UCAN, no sender key to the new leaf, no auto-accept — and surfaces the change to the human. §9.11's bullet list is the authoritative set of withheld acts, and this paragraph adds none. The one act that still takes a human step before it happens is an Add of a **new leaf for a flagged identifier**, which §9.11's outbound gate withholds; that is a question about admitting an identity, not about processing MLS.
**Rollback-resistance assumption.** The ≤ 5-min freshness guarantee (check 2) presupposes **rollback-resistant key-state resolution**. An attacker who serves an **OLD but validly-signed, lower-`seq`** chain as if it were a "fresh resolution" would return a **pre-rotation** key that the freshness check cannot catch — the chain is genuinely signed, only stale, so it passes as fresh. This is out of scope for the attestation verifier; it is mitigated at the **resolution layer** — the sequence rule of §9.6.1, which rejects a head of the accepted chain at a lower sequence than the accepted head, together with chain verification, which rejects a chain that recomputes to another identifier — which the attestation verifier **assumes**, rather than re-checking as a separate attestation check.

On key rotation (§9.7.3, §9.12), it is the **attestation** that is re-issued under the new `#active` key (a fresh signature over the leaf keys), not a leaf key made equal to the rotated identity key; outstanding KeyPackages carrying an attestation signed by the old key MUST be deleted from relays and replaced. Checks 1 and 2 together bound how long a retired `#active` keeps verifying an outstanding attestation: a verifier holding a pre-rotation key state inside the bound resolves the retired key until that entry ages out, so revocation is near-immediate rather than instantaneous. **That same entry runs the other way too**, failing the rotating identity's own fresh attestation at check 3, and the re-resolution obligation of the **Resolution failure policy** above is what stops it. This is the revocation lever exercised in §9.12.

**Group context extensions for nesting.** Child contexts include parent context IDs and governance configuration hashes in the MLS `group_context` extensions field (§5.13.3). This cryptographically binds the parent lineage to the child's group identity — the derived `group_id` is a function of the parent references. Root contexts (no parents) have empty nesting extensions.

**Authentication Service design:** MLS delegates identity verification to an Authentication Service (AS). In SCP, the AS is fully decentralized: DID resolution provides the public key binding, and UCAN validation provides the capability binding. No centralized AS server exists. Each participant independently verifies credentials by resolving the DID and validating the UCAN chain.

**Key conditions, the content boundary, and the relying party's obligation.** R8 obliges the latest state-carrying event of an identity's key-event log to list every key that appeared on the chain, each with its role, and each listed key is in exactly one of four conditions: **`current`** — listed in a role; **`Superseded`** — listed outside every role, because a later key took the role this key held; **`Retired`** — listed outside every role, with no successor key in the role it held; or **`Compromised{from: N}`** — listed outside every role, carrying a position N in the key-event log, at or before the sequence of the event that carries the entry, from which the standing root asserts an attacker held the key. ADR-063, the inception-derived key-event-log identity substrate, fixes these four names and makes the standing root the authority that asserts them: §9.7.4.2 R3 makes every state-carrying event root-signed, so a condition survives compromise of the operational key it concerns without that key's cooperation, and it names a reason the retiring key could not name once that key is the thing being disavowed. A verifier reads the condition the entry carries and derives none of it from the roles. R8 states the obligation to list every installed key exactly once, and a verifier applies R8's text rather than a paraphrase of it.

**What each condition decides, and what it does not.** The three conditions other than `current` share one criterion: the key signs nothing new, and content the party accepted before that key's boundary in a context stays valid there. `Superseded` and `Retired` decide nothing beyond it, so no verification rule branches on which of the two an entry carries; they differ only in the reason the standing root records. `Compromised{from: N}` alone adds a test on the signer's log-anchored evidence, and the paragraph **Why the log-anchored class exists, and the limit it carries** below is the one home of that test. **Where a rule anywhere in this spec calls a key *retired* in plain words, it means a key the latest state-carrying event lists in any of the three conditions other than `current`**; where a rule writes `Retired` in code font it names that one condition and no other. The controller withdraws a false alarm by a later state-carrying event that lists the key `Superseded`, `Retired`, or in a current role. An entry identifies its key by the public key bytes. **How a verifier resolves a `signing_key_id` fragment, stated once.** The fragment names a role, and the latest state-carrying event lists every key that ever held that role (§9.7.4.2 R8). For a **content-class** signature (the table below) the verifier considers every key that event lists as having held the named role — the key state carries each key's role beside its condition (§9.7.4.2 definitions), so that set is computable from the snapshot and admits no former root member into an operational role — takes the key whose bytes verify the signature, and then applies that key's condition and that context's boundary to the result; a verifier that read the `current` key alone would reject every message an author signed before its last rotation. For an **attestation-class** signature the verifier reads the `current` key of the named role and no other key (check 1 above). A verifier resolves a fragment through the latest state-carrying event in both cases, and never from a list of current keys alone.

**Where the content boundary lives.** Content signed by an operational key is committed inside a context through MLS, and **the retiring identity owes an MLS Update to every context it belongs to** — a Commit, an epoch boundary every member of that context observes identically. Three rules place that obligation on it: the compromise recovery protocol (§9.12 step 2) on a compromise, the rotation rule of §9.7.3 on a planned rotation, and §9.7.4.2 R4 on the abandoning controller before it publishes. **The obligation is the identity's, and a context where the identity did not discharge it records no Commit**; the paragraph below states what a member reading such a context does. **The epoch of the Commit that follows a key's retirement is that key's boundary in that context**, whatever the reason for the retirement. The position N of a `Compromised{from: N}` entry names where in the log the standing root asserts the compromise began; the Commit epoch names where that assertion took effect in each context, and content is ordered against it by **the MLS epoch the message decrypted under, never the envelope's `epoch` field** — a compromised key's holder signs that field, so a verifier that read it would take its ordering input from the attacker (§9.8.1 inner check 1 rejects an envelope whose `epoch` field differs from the epoch that decrypted it). No further ordering structure is needed: the decryption epoch is what MLS already gives every member, and every member derives the same epoch sequence, so the boundary converges by the same mechanism that makes MLS work.

**The boundary in a broadcast context.** A broadcast context (§5.14) runs no MLS group and advances no epoch: its authors distribute per-author sender keys and stamp each chunk with the author's `key_epoch`. **In a broadcast context the boundary for a retired author key is that author's `key_epoch` at the rotation, read from the sender-key distribution the author published and never from the chunk's own field**, for the same reason the MLS rule reads the decryption epoch: the holder of the retired key signs the chunk. **That distribution also records the author's highest chunk sequence at the step**, and a subscriber accepts a below-step chunk only at a sequence at or below the recorded value. **A subscriber that holds a distribution recording the step orders that author's chunks against both values**: it accepts a chunk whose `key_epoch` is below the step and whose sequence is at or below the recorded sequence, and rejects every other chunk under that key. **A subscriber that holds no such distribution reports `Invalid{no_boundary}` for that key** and re-fetches the author's sender-key distributions from the relays the author's service record names (§9.16.2). **The two arms are asymmetric, and the sequence anchor is what the broadcast arm has instead.** The MLS arm closes by destruction: §9.7.2 destroys the old epoch secrets after a 30-second grace, so no holder of a retired key can produce a message a member can still decrypt before the boundary. §9.16.5 retains old sender keys indefinitely by design, so the broadcast arm destroys nothing and a holder of the retired key could otherwise mint new chunks below the step at any later date; the recorded sequence is what bounds what it can mint. The outcome is recoverable and it fails closed: the subscriber verifies nothing under that key until a distribution reaches it, and it never accepts a chunk on the ground that it read no step.

**Abandonment sets a boundary for every key the final state lists `current`.** The abandoning controller's §9.12 step-2 Commit is the boundary in its context for every such key (§9.7.4.2 R4), so the content row below applies to an abandoned identity with no extra condition: under any key for which the context holds a boundary, the party accepts only content that reached it under an epoch before that boundary.

**"No boundary here" is a fact about the context, not a gap in the evidence.** This paragraph governs an MLS context; the broadcast arm above governs a broadcast context, and a member applies exactly one of the two. The boundary for key K in context C **exists iff C's Commit history records a retirement Commit from that identity for K**. A member reading C's Commit history, live or through a snapshot that carries that history, and finding no such Commit accepts K's content in C **on one further condition: C's Commit history records at least one Commit from that identity whose leaf attestation verified under K**. That condition is what makes the absence informative — a context that watched the identity sign under K would have watched it retire K, so the absence of a retirement Commit there says K was not retired. **A member that finds no such Commit reports `Invalid{no_boundary}` for K in C** and accepts nothing under K there: C never saw K, so C's silence about K's retirement is silence about a key C knows nothing of, and reading it as acceptance would admit content signed under a key retired before the identity ever joined C. The same condition governs an abandoned identity's keys that the final state does not list `current`. `Invalid{no_boundary}` is also the outcome when **the member holds no Commit history covering the span it must judge**, so it can neither find a retirement Commit nor establish that none exists. Both are the fail-closed direction, because a member that accepted content over a span it cannot see, or under a key its context never watched sign, would accept everything an attacker signed after a boundary it never read.

**The boundary travels with the content it bounds, and observation outranks it.** A context snapshot and a context export carry, for every identity whose key the context retired, that key's boundary epoch in that context, and the producer signs those values with the key the snapshot or export is signed under. A member that joins after the boundary Commit therefore learns the boundary from the snapshot it syncs rather than from an observation it could not have made. **Precedence:** a member's own observation of the boundary Commit outranks any snapshot value for that key in that context, so no other member rewrites a boundary the member watched happen. **A snapshot's boundary value is adopted only where the snapshot carries the Commit history supporting it**, whether the member holds one such value or two, and the member reports `Invalid{no_boundary}` for the span otherwise. Where the member holds two supported values that disagree, it adopts **neither**, reports `Invalid{no_boundary}` for the span they disagree over, and surfaces the disagreement to the user. Writing the check inside the two-value branch alone would leave the one-value case — a joiner syncing a single snapshot, which is the common case — adopting whatever boundary the producer asserted. **A producer asserts a boundary only from Commit history it holds**, and a producer that holds no history covering the epoch it names asserts nothing for that key. Taking the earlier of two disagreeing values would hand any co-member a signed erasure of any other member's history in that context, because the earliest value bounds the most content and a producer chooses the value it signs.

**The relying party's obligation, stated over evidence it holds.** For a retired key, a relying party accepts a signature **iff** the content reached it under an epoch **before that context's boundary** for that key. One test decides it, and the test reads two inputs the party holds: the epoch the content came in under, and the boundary value. The epoch is the MLS epoch under which the party decrypted the content, with a valid `membership_tag` (§9.8.1 check 2), for content the party received live; for content inside a snapshot or an export it is the epoch the producing context recorded for that item, attested by the producer on the snapshot. The boundary value is the one the party observed at the boundary Commit, or the one the snapshot or export carried to it under the precedence above.

**Which context's boundary a cross-context artifact is compared against.** "That context's boundary" is the boundary of the context **through which the relying party accepted the content**. A cross-context receipt that Bob accepted in context B is therefore compared against B's boundary for the signer, under the evidence B gave Bob, and Bob needs no membership in the producing context to verify it. A party verifies content only through a context it belongs to, on the evidence that context gave it, and holds no evidence about a context it never joined.

A key the state does not list `current` is not a live signing capability, and the position N of a `Compromised{from: N}` entry never unmakes what the party already accepted before the boundary. The controller's key event is never rejected on account of content.

**Content verification returns `ContentVerdict`, and this sentence defines it because §9.7.4.2 R14 names this section as its home.** Its variants are `Valid`, `Unverified{reason}` — the resolution-failure posture this section states, where a verifier holds the artifact and has not yet resolved a key state fresh enough to test it — and `Invalid{no_prefork_basis | no_boundary}`, whose two payloads §9.7.4.2 R7 and `03-identity.md` §3.2.1 step 5 respectively define. **Every SDK binding carries the type name and all four variant names unchanged**, and a resolution never returns this type, exactly as content verification never returns R14's.

**Every signed structure is classified.** The table below states, for every registered separator that an operational key or root signs, which condition its signature verifies under. The default for a separator this table does not list is the attestation class.

| Class | Rule | Separators |
|---|---|---|
| **Attestation** — current key only | verifies against the identity's current key for that role (check 1 above); a retired key's signature never verifies | `SCP-KEYPACKAGE-ATTESTATION-V1:`, `SCP-ATTESTATION-V1:`, `SCP-PARTICIPATION-V1:`, `SCP-PARTICIPATION-PROFILE-V1:`, `SCP-KEY-REQUEST-V1:`, `SCP-ACCESS-KEY-REQUEST-V1:`, `SCP-EPOCH-ADVANCE-V1:`, `SCP-BLOCK-NOTIFICATION-V1:`, `SCP-CHALLENGE-REQ-V1:`, `SCP-CHALLENGE-RESP-V1:`, `SCP-CHALLENGE-VERIFY-V1:`, `SCP-BRIDGE-REGISTER-V1:`, `SCP-PUSH-REGISTER-V1:`, `SCP-PUSH-DEREGISTER-V1:`, `SCP-INVITATION-BUNDLE-V1:`, `SCP-JOIN-RESPONSE-V1:`, `SCP-SERVICE-RECORD-V1:` (the role is the service-key designation, `03-identity.md` §3.10.13), `SCP-RELAY-PROOF-V1:` (the role is the operator's `#active`; the row is stated rather than left to the default, because a proof is a live challenge-response and the operator's own rotation must revoke it — §9.7.4.2 definitions), UCAN tokens, and every separator this table does not list |
| **Content** — accepted before the boundary | the relying-party obligation above: verifies under a current key, and under a retired key only for content that reached the party under an epoch before that context's boundary for that key | `SCP-INNER-ENVELOPE-V1:`, `SCP-BROADCAST-ENVELOPE-V1:`, `SCP-VOTE-V1:`, `SCP-PROPOSAL-V1:`, `SCP-RECEIPT-V1:`, `SCP-XCTX-RECEIPT-V1:`, `SCP-XCTX-STREAM-RECEIPT-V1:`, `SCP-XCTX-DIVERGENCE-V1:`, `SCP-OUTLET-CHUNK-SIG-V1:`, `SCP-OUTLET-CREDIT-V1:`, `SCP-OUTLET-CANCEL-V1:`, `SCP-RESET-REQUEST-V1:`, `SCP-COMMIT-RANGE-REQ-V1:`, `SCP-COMMIT-RANGE-RESP-V1:`, `SCP-CHECKPOINT-V1:` |
| **Log-anchored evidence** — anchored to a key-state position | the artifact carries `key_state_head` inside the signed preimage (§9.5.2), which a cosigned head and a conflict statement carry under the name `witness_key_state_head` (§9.7.4.3). **`key_state_head` is the §9.5.1 preimage digest of the latest state-carrying event at or before the moment the signer signed** — the digest R13 takes over that event's signed preimage, naming the position at which this row's `current` test is read. This sentence is the one construction of the field, and §9.5.2 and §9.15 cite it. The signature verifies **iff** the signing key was `current` at that position, and, where the entry is `Compromised{from: N}`, only under the further test the paragraph below states. A key the state lists `Superseded` or `Retired` keeps its signature valid for this class, because the artifact names when it was made | `SCP-KEY-DESTRUCTION-V1:`, `SCP-CONTEXT-SNAPSHOT-V3:`, `SCP-CONTEXT-EXPORT-V3:`, `SCP-COSIGNED-HEAD-V1:`, `SCP-WITNESS-CONFLICT-V1:` |
| **Key event** — the log's own rules | §9.7.4.2 R3 | `SCP-KEL-EVENT-V1:` |

**Why the log-anchored class exists, and the limit it carries.** An artifact a party publishes as evidence against a future version of itself cannot verify under the attestation class, because the signer would void it by any routine rotation of the key it controls. §9.15's destruction attestation is such an artifact: it is published to relays, outside any context, so no context epoch orders it and the content class has no test to apply. **A witness's two objects are such artifacts**: a witness operator rotates its `#active` on its own schedule, and under the attestation class that rotation would void every cosignature and every conflict statement it ever signed, which is the historical record a relying party establishes past positions from. A durable context snapshot and a durable context export are such artifacts too, for a second reason: a snapshot signed under a key the producer later rotates is the record that teaches a later joiner where that key's boundary lies, and the content class would reject it at every member who received it after the boundary. Anchoring these artifacts to a key-state position gives them an ordering the signer cannot revise after the fact, because the log fixes the key-state head digest. **A relay proof of control is not such an artifact and the attestation row carries it**: it is a live challenge-response over a nonce one reader drew for one query, so it has no future version of itself to survive, and the operator's own rotation is meant to revoke it. **The limit, stated because it is not a guarantee against the compromised key's holder:** the signer chooses `key_state_head`, so a party holding a key the state lists `Compromised{from: N}` can anchor a forged artifact before N. A verifier therefore accepts such an artifact **only** when it held that artifact before it adopted the event that carried N — first-seen, recorded with the adoption. First-seen is the sole acceptance condition, because no section constructs a countersignature over one of these artifacts, so a verifier told to weigh one would invent the object and accept the exact forgery the sentence above describes. Against a compromised key with first-seen unmet, this class gives no guarantee, and a verifier rejects. `SCP-CHECKPOINT-V1:` (§9.9.3) needs no anchor at all: a member accepts a consistency checkpoint through MLS inside the context, so the content class already orders it. **Which artifacts are durable:** a context snapshot and a context export are durable artifacts, stored and re-served after the epoch that produced them, which is why they carry per-item epochs and their own key-state anchor; every separator in the content row is live traffic a context ordered when it arrived.

Governance votes and proposals are content: a vote cast under a key that is later marked compromised stays counted for the members who accepted it before the boundary, because the alternative — every vote in a context's history rejected the moment a key is asserted compromised — would let a compromise assertion rewrite governance outcomes. The key-event record frame carries no signature of its own (§9.10.12), so this table classifies none. A key-continuity fingerprint (§9.11) is a hash, not a signature, and is outside this table. Rationale for the default: a structure nobody classified is safer read as current-only than as content, because the content class admits historical keys.

**Every verdict the resolution policy must consume.** The resolution-failure policy of check 2 has, for each trigger, a branch for resolution failure and a branch for a resolution that returns a rotated key. The six verdicts of §9.7.4.2 R14 partition across those branches as follows, and the policy MUST route each one.

- `Adopted` is the **success** branch and it refreshes the accepted key state. `Confirmed` refreshes the verifier's liveness evidence and not the staleness clock, so check 2's bound decides what happens next exactly as it does for a discard (the policy above states why).
- `Discarded{accepted_head}` is **not** the success branch: the verifier stayed on the baseline it already held (§9.7.4.2 R12), so check 2's freshness bound decides what happens next exactly as it does for `Confirmed`. Routing a discarded stale candidate to the success branch would let a party that suppresses the newer head and serves an older genuine one pin every verifier on a baseline listing a stolen key `current`, at no cost and repeatably.
- `Inconclusive` is the **failure** branch: an Add rejects, and an already-admitted member's Update falls to the bounded last-known-good grace. A verifier reports the resolution failure by the cause the verdict names and never as a generic outcome.
- `Invalid{at_event}` **rejects on both triggers and never reaches the grace.** A chain the verifier has judged invalid is not a transient resolution failure, so an Add rejects, an already-admitted member's Update rejects, and the verifier MUST NOT fall back to a last-known-good key state for it. Routing it to the failure branch would hand the pin-to-stale attack to any party that can serve one invalid chain.
- `Contested` is its own branch, and §9.11's gate list is authoritative for the acts a verifier withholds from a contested identifier. Two things are decided here rather than there. **A leaf replacement is processed and recorded unverified**, under the uniformity paragraph above; the verifier checks the replaced leaf's attestation against no key state, because the party that authored the divergence chose where the two chains part and so chose the shared prefix, and a verifier that read the shared prefix's key state would take its verification basis from the attacker. **Leaf eviction:** the verdict alone evicts no leaf, and §9.12 step 1a proposes Remove for no leaf on a `Contested` verdict. **Content verification** for that identity uses the shared prefix's key state as its basis for content the member accepted under an epoch no later than the last Commit that context observed from the identity before the member first observed any divergent suffix (§9.7.4.2 R7), and verifies nothing after that anchor; the anchor reads what the member observed, never where the divergence's author placed the fork. **A contested identity acquires no new boundary from the contest**, because it retired no key in the contest and issued no §9.12 step-2 Update for it, so every boundary the shared prefix already set still binds. A member that cannot place content before the anchor reports `Invalid{no_prefork_basis}`.

A `RootRecovery` that is `Adopted`, and a `Contested` verdict, both set the identifier's `ContinuityStanding` to `PendingReverify` under §9.6.4, and an `Inconclusive` or `Invalid` first contact sets `Unresolved` there. §9.11's gate list states what each of the two withholds.

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

- Root set (P-256, one or more members with a signing threshold; §9.7.4.2 definitions): each member is generated in a substrate that holds a P-256 private key and never exports it. **The default substrate is a passkey** under the universal relying-party identifier the SDK ships (§9.7.4.1 item 4), and a FIDO2 token, an HSM, a platform secure element, and a software keystore each qualify as well. Used ONLY for establishment events (§9.7.4.2 definitions). It fixes a pre-rotation commitment only inside the inception event; after inception, only a reveal-authorized event fixes a new commitment, and the root alone never re-commits (§9.7.4.2 R1). The identifier is the inception event's digest (§9.7.4.2 R2), not a derivation of any key, and it never changes.
- Active Signing Key (P-256): Generated via KeyCustody. Used for MLS KeyPackage attestations (§9.7.1), inner-envelope signatures, UCAN issuance. It does NOT sign the MLS leaf/credential directly — the leaf is self-signed by the ephemeral MLS leaf signature key (below), and the DID↔leaf binding is carried by a `#active`-signed KeyPackage attestation. Rotated by a `KeyState` event signed by the standing root (§9.7.4.2 R3). The identifier does not change on active key rotation.
- Next set (P-256, one or more pre-rotation keys with a next threshold): generated at identity creation and again as the successor set at every reveal (§9.7.4.1 items 1, 6), held in custody independent of the operational path (§9.7.4.1 item 3a). **The default substrate is a second passkey created ahead of the reveal that will consume it, under the same platform account that holds the root credential** (§9.7.4.1 item 4, which discloses that co-residence and states what the SDK offers in its place). Each member is a one-shot authorizer: it signs exactly one reveal-authorized event (§9.7.4.2 definitions) and is then spent and destroyed (§9.7.4.2 R5); it never becomes a root member or any other key.
- MLS leaf HPKE keys (DHKEM(P-256), 65 bytes each) — these are **three distinct** keys, NOT one; RFC 9420 keeps them separate and so does SCP:
  - LeafNode `encryption_key`: the **ratchet-tree** HPKE key (RFC 9420 §7.2) to which path secrets are sealed on Commits. Lives on the leaf in the ratchet tree. Generated by the MLS library per the selected ciphersuite, stored in platform secure storage, re-generated on every Update/PCS rotation.
  - KeyPackage `init_key`: the HPKE key the Welcome's `EncryptedGroupSecrets` is sealed to at join (RFC 9420 §7.1). **`init_key != encryption_key`** — it lives ONLY in the published KeyPackage, is single-use, and is **consumed at join** (never enters the ratchet tree). It is the read-at-join vector, which is why the KeyPackage attestation binds it and the verifier checks it at Add/Welcome time only (§9.7.1, §9.5.2).
  - `scp_wrapping_key` (`0xFF01`): the stable DHKEM(P-256) HPKE key used to wrap §9.16 per-sender key distributions (§9.16.2). Published as a LeafNode extension; distinct from both keys above and does not rotate on epoch advance.
  All three are bound to the DID by the KeyPackage attestation (§9.7.1, §9.5.2) and are distinct from the leaf signature key below.
- MLS leaf signature key (P-256, in RFC 9420's uncompressed SEC1 encoding): The leaf's `signature_key` — an **ephemeral, context-scoped** key generated by the MLS layer (`SignatureKeyPair::new()`), one per group, re-generated on every Update/PCS rotation (§9.7.3). It self-signs the LeafNode and is DISTINCT from every root member and from the Active Signing Key (`#active`) — it is never a DID verification method and MUST NOT be expected to resolve to one. It is bound to the member's DID out-of-band by the `#active`-signed KeyPackage attestation (§9.7.1, §9.5.2), which is re-issued whenever this key is re-generated. Never persisted beyond the MLS group state; destroyed with the leaf on Update or group exit.
- KeyPackages: Pre-generated and published to relays. Each KeyPackage is single-use. The SDK MUST maintain a buffer of at least 10 unused KeyPackages per identity on relays. Replenished when the buffer drops below 5.
- UCAN signing key: Active Signing Key (P-256, signing under ES256) for root UCANs. UCAN tokens are signed by the human's Active Signing Key — never by a root member. On active key rotation, existing UCAN tokens are revoked and reissued under the new Active Signing Key. Agent-autonomous actions use scoped UCANs that the human's Active Signing Key issues to a delegated agent identity as the token's audience. That agent invokes such a token under its own `#active`, and no agent signs the human's root UCAN.

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

**1. Generation.** The controller generates the pre-rotation private key inside the substrate that will hold it, from that substrate's own random source, and no party outside that substrate ever holds it, because a key a third party generated is a key a third party keeps.

Three readings of that rule cover the substrates item 4 admits, and they add nothing to it: a substrate that generates its own key receives no key material from the SDK and returns none; a substrate the SDK fills takes a key the SDK generated on the device from the platform CSPRNG; and a network HSM under a separate principal is the substrate and not a remote server.

**2. Publication.** The pre-rotation commitment is a field of the inception event and of every reveal-authorized event, and the controller publishes the commitment alone. The public key appears only inside the reveal-authorized event that consumes the commitment. KERI states the same under `spec-body` §Pre-rotation, whose `n` field carries the digests of the next keys and never the keys.

**3. Separation.** The controller MUST store the pre-rotation private key separately from every root member and from the Active Signing Key, and MUST NOT leave it reachable through the custody provider or the authentication flow that daily operations use.

**3a. Independent residence.** The recovery authority is the minimal secret, key handle, or authorization capability sufficient to recover the pre-rotation private key. It MUST reside in a substrate whose compromise is independent of operational-custody compromise: no secret, handle, or capability reachable directly or transitively from the operational `KeyCustody` provider or from the daily-operations authentication flow may suffice, alone or together with publicly stored artifacts, to recover it. Wrapping the key in a cipher whose decryption authority is itself reachable from operational custody gives zero protection against the adversary this rule names.

Where no substrate satisfying that requirement is available, identity creation MUST fail closed with a typed error, and the same refusal binds at every later reveal: the SDK MUST refuse, with a typed error, to compose a reveal-authorized event at all, before it signs. There is no fallback to co-located operational storage and no fallback to a development stand-in. The ceremony order of §9.7.4.2 R10 puts successor generation ahead of the persist and the signature, so the refusal lands in the one phase where an abort still leaves the standing commitment unconsumed.

A reveal-authorized event is a rare, separately authorized event and not a daily operation, so a distinct reveal-time authorization principal satisfies the residence requirement even where that principal is fully automated. What fails the requirement is the daily operational signing flow being able to reach the pre-rotation key.

The requirement binds the key at rest and during daily operations: through an authorized rollover or recovery the pre-rotation key signs the event where it resides, and the controller never imports it into operational custody.

**4. Custody selection.** Under the key-event log a copy of a pre-rotation key alone does more lasting damage than a copy of the root alone. A root leak is recoverable by a reveal, while a leaked pre-rotation key lets its holder contest the identity at any later date and, held exclusively, take the identity over and then kill it permanently.

Custody is ranked on two axes, with post-spend destructibility as the primary axis and theft resistance at rest as the second.

**The custody profile.** The SDK computes a `CustodyProfile` from one question with three answers: does this platform expose a WebAuthn credential API this process may call, and if so does that API arrive through a desktop platform credential provider, a mobile one, or a page's `navigator.credentials`. The four values are `Headless`, `Desktop`, `Mobile`, and `Browser`, name-bound under the criterion §9.7.4.2's definitions state, so a later revision registers a fifth value under one name in every binding. "Consumer profile" names the union of the last three and is shorthand rather than a fifth value. Whether a human attends decides nothing.

A profile is a property of a running SDK and never of an identity. The SDK MUST re-surface the copyable-custody disclosure whenever it opens an identity whose standing pre-rotation custody type is one of the three copyable values, on whatever profile it runs, because an identity incepted headless under a copyable method keeps that key when its operational key migrates to a phone.

**Consumer methods.** The consumer profile carries three pre-rotation methods and every one of them is non-exportable: a passkey, which is the default; a FIDO2 security token; and an HSM-resident key under a principal the operational path holds no grant to assume. A non-exportable substrate is one from which no code path extracts the private key. The controller holds no exportable copy, and the provider's sync fabric may retain an encrypted copy reachable only through the platform account. Alec ruled on 2026-09-10 that self custody "is writing down a key, yes" and is "not a concern", which is why the three copyable methods sit on the headless profile alone.

A passkey is a discoverable WebAuthn credential under the universal relying-party identifier the SDK ships, `ctx.network` by default, held by the platform's passkey provider and synced across that account's devices. Its private key is non-exportable, so the controller holds no second copy of it. Alec named the substrate on 2026-09-10, "a passkey in your apple passwords or similar", and typed the domain rule the same day: "roots would get created under a universal identifier by default like ctx.network". Two questions about that identifier are open at Alec's instruction, and `00-open-questions.md` §Identity and Custody carries both as a dated entry; no sentence of this section accepts, mitigates, or moves the default.

A passkey provider's sync fabric may retain an encrypted historical copy of a credential the controller deleted, and the controller cannot verifiably purge that copy. The retained copy is reachable only through the platform account, which makes it a platform-account exposure and never a loose-key exposure, and which makes whoever holds that account a copy holder for the four-cell table below.

The root credential and the pre-rotation credential share one platform account by default, so the default places the identity's root authority and its recovery authority behind one authentication factor. Alec chose that default on 2026-09-10 from two options the orchestrator put to him: keep the two together and tell the user.

The SDK MUST state the co-residence at custody selection, and MUST offer the pre-rotation credential on a FIDO2 security token or under a second platform account. That offer binds the SDK and not the controller.

**One disclosure rule.** At custody selection, on every profile, whenever the selected pre-rotation method is copyable or carries a provider-retained copy, the SDK MUST state the residual row of the four-cell table that applies, in that table's own terms. The rule reaches the three headless copyable methods, the passkey's provider-retained copy, and the second-platform-account separation alike, because the second-account branch reaches a retained copy of a spent credential through that second account's later holder, which makes its residual real rather than nominal.

The independence test of item 3a reads operational custody and never the root, so it does not fire on the root-and-recovery co-residence, and item 3a's fail-closed rule governs the operational path alone.

A verifier reads no relying-party identifier when it verifies an identity. It verifies an identifier and a key state, and neither of those carries one. The value `SHA-256(rpId)` travels inside the WebAuthn assertion and is public in the log.

**Headless methods.** The headless profile carries three copyable methods, and the SDK offers them on `Headless` and on no other profile: an encrypted offline backup under AES-256-GCM with an Argon2id-derived key under the codebase's one parameterization, which `17-persistence-and-storage.md` §17.8 states; a 3-of-5 Shamir split over GF(2^8) with 34-byte shares; and a 24-word BIP39 paper mnemonic.

Where the SDK auto-generates the passphrase for an encrypted offline backup, it MUST generate that passphrase with at least 128 bits of entropy.

Each copyable method yields key bytes, so a copy can outlive the reveal that spent it. Where a copy of a spent pre-rotation key later reaches any party, that party forks below the event that spent the key and reveals the same commitment there, and the root rule of §9.7.4.2 R6 alone decides the outcome.

**The four-cell outcome table.** The controller's own revealing event either carried the standing root's signature or it did not, and the copy holder either holds that root or does not.

| The controller's revealing event | The copy holder holds the root | The copy holder holds no root |
|---|---|---|
| Carried the standing root's signature | Both suffixes are rank 1; the identity is contested, terminal by key material | The controller wins outright |
| Carried no root signature | The fork wins outright | Both suffixes are rank 2; the identity is contested, terminal by key material |

A root signature on the controller's own revealing event therefore never guarantees a win. Against a root-holding leaker, co-signing buys the difference between losing the identity and contesting it.

**Method by profile.** "Conforms" means the SDK MAY offer the method on that profile, and "does not conform" means the SDK MUST NOT offer it there.

| Custody type | Headless | Desktop | Mobile | Browser |
|---|---|---|---|---|
| `Passkey` | no | yes | yes | only from an origin whose effective domain is the relying-party identifier the credential was registered against, or a registrable-domain suffix of it |
| `Fido2Token` | yes | yes | yes | yes |
| `Hsm` | yes | yes | yes | no |
| `EncryptedOfflineBackup` | yes | no | no | no |
| `ShamirShares` | yes | no | no | no |
| `PaperBackup` | yes | no | no | no |
| `SecureEnclave` | no | no | no | no |
| `AndroidKeystore` | no | no | no | no |
| `Software` | no | no | no | no |

`SecureEnclave` and `AndroidKeystore` fail item 3a by construction, because the operational key sits in that same keystore under that same application principal. `Software` is the operational path's own substrate and is copyable.

No row of the table turns on whether a human attends the reveal. Every conforming answer stays subject to item 3a, and the SDK MUST reject a selection whose recovery authority is reachable from the profile's operational custody, whatever the table says.

**What a one-member next set costs.** A 1-of-1 next set is the single-custody-loss configuration: one loss of one key hands a party everything every row of the failure-mode table that turns on a pre-rotation key needs. A next threshold of two or more with members in independent custody raises that precondition, §9.7.4.2 R3 already permits it, and reserve rotation is the mechanism that makes it affordable, because a reserve holder's key survives an event it did not authorize.

**5. The ceremony at creation and before every reveal.** At identity creation, and again for the successor key before every reveal-authorized event, the SDK MUST (a) generate the pre-rotation keypair, (b) present the custody options on both axes, (c) guide the user through the selected method, (d) confirm the key is reachable, (e) sign and publish the event that carries the commitment only after that confirmation succeeds, and (f) destroy the pre-rotation private key from the creating device's memory.

The reachability confirmation of step (d) for an offline method is a re-entry or a re-scan of the backup. For a non-copyable substrate it is one test signature from the credential over `SHA-256("SCP-CUSTODY-PROBE-V1:" ‖ 32 fresh random bytes)`, verified against the public key the commitment covers; for the assertion form the probe's WebAuthn challenge is that same prefix over those same random bytes. Without a defined confirmation the gate had a precondition for a mnemonic and none for a passkey.

The probe separator is what stops the probe being a key-event signature. The string `"SCP-CUSTODY-PROBE-V1:"` differs from the key-event preimage separator and from the WebAuthn-challenge prefix that §9.7.4.2 fixes, so no probe value equals either, and an assembling device cannot offer the digest of an event it composed as the value to sign.

On a non-copyable substrate no private key ever entered the SDK's memory, so step (f) has nothing to destroy and the SDK discharges it by holding no key material. A reader should not take an unconditional destroy step as evidence that the key passed through the SDK.

**6. Every reveal fixes the next commitment.** Every reveal-authorized event fixes the next pre-rotation commitment inside that same event, and the successor key follows items 1, 3a, 4, and 5b through 5d before the event is signed. KERI states the same under `spec-body` §Rotation using pre-rotation, where every rotation event fixes a new `n` list so that rotation authority never exhausts.

**7. Periodic reachability prompts.** The SDK SHOULD prompt the user to verify that the pre-rotation backup is still accessible, about every six months. That prompt is a client-level reminder and not a protocol enforcement, because the protocol cannot verify that an offline backup still exists.

**8. Retention.** The controller MUST retain every standing pre-rotation private key from the moment the commitment list is fixed until a reveal-authorized event supersedes that list, on every code path, and that obligation covers every member of the set whether a reveal named it or not. Loss of a standing key forecloses both reveal-authorized kinds, because the standing root alone cannot fix a new commitment. At the superseding event the obligation ends for each key the reveal revealed and for each member the superseding list drops, and it continues for each unexposed member the superseding list re-commits.

**Failure modes.** Each row follows from the root rule of §9.7.4.2 R6 and from nothing else. "P" names the pre-rotation key.

| What happened | Outcome |
|---|---|
| P lost, root intact | The identity operates and cannot roll over, recover, or abandon |
| P and root both lost | Both parties sit at rank 3 and no later event ends the tie |
| P copied, root intact and trusted | The controller wins outright |
| P copied, root lost | Rank 2 on both sides; terminal |
| P held exclusively by the attacker | The attacker takes the identity and can then kill it permanently |
| A copy of P forks before an abandoning rollover | The controller's rank-1 suffix wins |
| Root compromised, P held only by the controller | The controller wins |
| Root compromised, P copied | Rank 1 on both sides; terminal |
| Two of the controller's devices both hold the root | Rank 3 on both sides; pending |

Where the root cannot be recovered by key material, the person establishes a new identity, and each context's admins remove the old identity and admit the new one after confirming the head from a relay in the fallback set. The social recovery of `03-identity.md` §3.3 does not apply, because that procedure re-establishes custody of the same identity.

### 9.7.4.2 Root-Authority Recovery and Fork Precedence

This section governs a non-delegated identifier, one whose key state carries the all-zero delegator placeholder. For a delegated identifier the delegator's chain anchors the delegate's establishment events by a key-event seal, so precedence reads the delegator's chain, and R3 rejects every chain carrying a nonzero delegator.

#### Definitions

**The root set.** The root of an identity is a root set: an ordered list of at most `MAX_ROOT_SET_SIZE` public keys with a signing threshold t. A personal identity is the one-member case. Alec ruled the shape in on 2026-09-03: "if we can support orgs we should." An identity that several officers jointly control, none of them able to act alone, is in scope, and the identifier is the inception event's digest, so the shape is day-one. KERI defines the same two fields under `spec-body` §Key list field and §Key and key digest threshold fields; the 16-member cap is SCP's, because KERI bounds no list.

**A root signature is an indexed signature group.** The signed preimage names the root-set indices that sign and the signature form of each named index's slot. The signature field carries exactly one slot per named index, in index order. Every indexed signature MUST verify against the member at its index, and the named indices MUST number at least t and MUST be distinct. A fixed-layout signature set and a threshold of "at least t members" contradicted each other, and KERI's `spec-body` §Indexed Signatures resolves that without a variable layout.

**The standing root** at a position is the root set and threshold that the latest root-installing event at or before that position installed. The inception event installs the first, and a `RootRecovery` installs each later one.

**Signature form.** A slot's signature form is a one-byte discriminator carried in a signature-form list that the preimage binds beside the signer index list of its group. Its type name is `SignatureForm` and its two variant names are `Raw` and `WebAuthnAssertion`, name-bound under the criterion below. A verifier MUST reject any other value.

`SignatureForm::Raw`, discriminator `0x01`: the slot is the 64-byte raw ECDSA signature that §9.5 defines, low-`s` normalized by the signer, verified against the key at the slot's index over the event's preimage digest.

`SignatureForm::WebAuthnAssertion`, discriminator `0x02`: the slot is

```
BE32(len(authenticatorData)) ‖ authenticatorData ‖ BE32(len(clientDataJSON)) ‖ clientDataJSON ‖ signature
```

where `len(authenticatorData)` lies between `MIN_AUTHENTICATOR_DATA_BYTES` and `MAX_AUTHENTICATOR_DATA_BYTES`, `len(clientDataJSON)` lies between one byte and `MAX_CLIENT_DATA_JSON_BYTES`, and `signature` is 64 raw bytes. The signer converts the authenticator's DER `ECDSA-Sig-Value` to `r ‖ s` and low-`s` normalizes it, and a verifier reads 64 raw bytes and never DER. A WebAuthn authenticator signs its own envelope rather than a preimage handed to it, so the default root custody of §9.7.4.1 would otherwise produce an unparseable inception event.

The assertion form is admitted at every indexed signature group and not at the root group alone: the reveal group, the installed-set K′ group, and the standing-root group. A passkey is the default substrate of a pre-rotation key as well as of a root member, and an SDK generates K′ in operational custody that may also be a passkey.

A verifier of an assertion slot parses `clientDataJSON` as RFC 8259 JSON and MUST reject a document carrying a duplicate member name at any nesting level, because JSON parsers differ over which duplicate wins and two honest verifiers holding one chain would then disagree about one event's validity.

A verifier MUST reject an assertion slot unless the `type` member equals `"webauthn.get"`, and unless the `challenge` member equals the unpadded base64url encoding of `"SCP-KEY-EVENT-V1:" ‖ D`, where `D` is that event's own preimage digest. Both comparisons run against the decoded JSON string value and never against the raw bytes. The challenge prefix is what makes a sign-in assertion unusable as a key-event signature, and the decoded-value comparison is what stops two verifiers comparing different things, because RFC 8259 admits an escape for any character.

A verifier MUST reject an assertion slot unless the user-presence flag is set in `authenticatorData`, which is bit 0 of byte 32, and MUST reject a signature that fails the low-`s` rule of §9.5. It then verifies the 64-byte signature against the key at the slot's index over `authenticatorData ‖ SHA-256(clientDataJSON)`, which is the message WebAuthn defines and is not `D`. `MIN_AUTHENTICATOR_DATA_BYTES` is what guarantees byte 32 exists before the verifier indexes it.

**Operational keys.** An operational key is a signing key other than a root member, and the Active Signing Key `#active` is the identity's one operational role. Alec ruled on 2026-09-05: "overturning the shared agent it is necessary because we are literally getting rid of did. This is something I told you to do."

**Key algorithm.** A key's algorithm is a one-byte discriminator carried beside that key by every state-carrying event, and by the inception event for every key it installs and every commitment it fixes. Its type name is `KeyAlgorithm`, exactly one variant is registered for v1, `EcdsaP256Sha256` = `0x01`, and a verifier MUST reject an unrecognized value. The field exists from the first schema version because the identifier construction freezes the inception preimage. KERI carries the same information in the derivation code of KID0001, on every key primitive.

**Establishment events.** Every key event is an establishment event. The root signs establishment events and nothing else, and operational keys sign content and attestations and never sign an establishment event. Alec settled the distinct root authority on 2026-08-30: "yes keep #0 as root we like this design so far". The signing separation is the executor's, decided under that ruling: it lets a controller retire a compromised operational key without the root's cooperation being in question, and it keeps the root cold.

**Sequence.** An event's sequence is its predecessor's plus one, and the inception event's sequence is zero, so chain order and position order are one order and every rule that says "position" means the sequence. Nothing else ties the sequence field to the digest chain, and without that tie an attacker choosing sequences would choose which verifiers accept a snapshot. KERI states the same under `spec-body` §Sequence number field.

**The community relay list** is a single artifact the SDK ships: a fixed list of relays, each entry declaring the operator identity that runs it, published with the SDK and identical in every binding of one release. `18-addressability-and-deployment.md` §18.5.1 defines the artifact and its entry shape, and that section and this definition are the only two homes.

The artifact carries two roles: it is the source of the fallback set, and it is the SDK's default recognized set. Neither role decides whether an event is valid or how a fork ranks.

**The fallback set** for an identity is the entries of the community relay list that the identity's own service record does not name, and where that set is empty it is the community relay list itself. A reader holding no accepted service record takes the whole list. The exclusion exists because the holder of the designated key chose the relays the record names; the non-empty rule closes the exclusion's own failure, since a party holding that key could name every entry and leave nothing.

The fallback set is not a priority order and no rule reads one. A relay a deployer configured, a relay a peer advertised, and a relay the identity's service record names all sit outside the fallback set unless the community relay list carries them.

**The next set** is a list of at most `MAX_NEXT_SET_SIZE` pre-rotation public keys whose commitments the chain fixes, with a next threshold n. A reveal is an indexed signature group over that set: the preimage names at least n distinct indices and their forms, the revealing event carries the public key for each named index, and the signature field carries one slot per named index. KERI defines the same under `spec-body` §Next key digest list field and §Key and key digest threshold fields, with the doubly indexed signature that verifies a revealed key against its prior digest.

The pre-rotation key P names one member of the next set. Each member is a one-shot authorizer that signs exactly one reveal-authorized event and is then spent and destroyed, and never becomes a root member or any other key.

**Custody type.** A key's custody type names the substrate that holds its private half. Its type name is `CustodyType` and every SDK binding carries that name and its nine variant names unchanged: `Passkey`, `Fido2Token`, `Hsm`, `SecureEnclave`, `AndroidKeystore`, `EncryptedOfflineBackup`, `ShamirShares`, `PaperBackup`, `Software`.

Every custody-type value names a substrate that holds a P-256 key, so no custody type is barred at a root member and a verifier rejects none on that ground. What constrains a selection is the principal-distinctness test of §9.7.4.1 item 3a, which no verifier can check from signed bytes and which the SDK enforces at selection.

The custody type is a declaration its author chose, and every consumer reads it as `Software` unless a platform proof verifies. Alec ruled on 2026-08-25: "either the platform proof is attached and verified, or the custody model reads as software no matter what string was written".

The key state carries no platform proof, and adding a proof field is a separator-version bump that invalidates every signature made under the old separator, so the key-state custody type is permanently advisory and the verifiable declaration lives in the custody-attestation artifact that `27-attestations.md` owns.

Every key the key state names carries a custody type, and that includes each member of the next set, because the next set otherwise left the substrate holding the identity's recovery authority as the one substrate no other party could read anything about.

**The key state** of an identity is: the standing root with each member's custody type; every operational key that is `current`, by role and by custody type; each member of the next set with its custody type and key algorithm; the witness set with the witnessing interval; the service-key designation; and the delegator. The key list names every key `current` at that position and, on a `RootRecovery`, every key whose condition that event changes. It names no other key, so the key state's size follows the identity's current configuration and never the chain's length. A verifier replays the log under R8, so restating every key the chain installed would make every state-carrying event grow with the square of the installed-key count and would tell a verifier nothing the replay does not. KERI's key-state notice carries the same shape, under `spec-body` §Validator and KID0003 §Key State Notice Messages.

The verification-relationship arrays of the retired DID document are expressed by the key state: a key's role and its condition say what that key may do, and no separate relationship list exists.

The key state carries no relay endpoint, no private-state location, and no capability URI. Every transport and service field lives in the service record instead. The identifier's value would otherwise depend on the initial relay list, and a relay change would need a root threshold against a root the controller keeps cold.

The inception event fixes the initial value of each key-state field and does not freeze the field. Every state-carrying event carries the whole key state, so a later `KeyState` changes the witness set, the witnessing interval, the service-key designation, the operational roles, and each key's condition. The one field the inception freezes for the life of the identity is the delegator, because a delegated chain's precedence reads a different chain and a verifier must know from the first event which chain that is.

**State-carrying events.** A state-carrying event carries the complete key state. Three kinds carry state: the inception event, a `KeyState`, and a `RootRecovery`. The derived key state at any position is the key state that the latest state-carrying event at or before that position carries, and no earlier event contributes.

**The key-event seal** is a digest, carried by a `KeyState`, of another identity's key event, under the preimage `SHA-256("SCP-KEL-SEAL-V1:" ‖ anchored_event_preimage_digest)`. One seal anchors one key event and plays no part in content verification. KERI's `spec-body` §Key Event seal carries the fields `[i, s, d]`, from which SCP drops the arbitrary-data anchoring because SCP content commits through MLS.

The seal has no live reader today, because R3 rejects every chain whose delegator is nonzero until the delegation model is specified. It ships now because adding the field later would bump the separator version and invalidate every signature made under the old separator.

**The pre-rotation commitment** is `SHA-256("SCP-PREROTATION-COMMITMENT-V1:" ‖ pre_rotation_public_key)` over one member of the next set. The chain fixes the commitment list and the next threshold together, and the public key is a fixed-length 33-byte SEC1 compressed point carrying no length prefix. KERI's `spec-body` §Next key digest list field carries the same per-key digest list, which superseded the XOR-combined single digest of KID0003.

**The standing commitment** at a position is the commitment list and next threshold that the latest commitment-fixing event at or before that position fixed, which is the inception event or a reveal-authorized event. KERI states the same under `spec-body` §General Pre-rotation, as the prior-next threshold and the prior-next key list.

A reveal-authorized event carries a reveal against the standing commitment at the event's predecessor. Each revealed key's commitment MUST be the member of the standing list at the index the preimage names, and the verifier checks the reveal against the standing commitment's next threshold and never against the threshold the event itself fixes. A reveal checked against its own event's threshold would let a holder of one member of a 2-of-3 standing set name one index, declare its successor threshold 1, and take the identity on a threshold the previous controller never set. KERI requires the same two separate checks under `spec-body` §General Pre-rotation.

**A witness** is a relay that an identity's key state designates to cosign that identity's log head. Alec ruled the layer's scope on 2026-09-10: "watch and report as well". Neither the cosigned head nor the conflict statement enters any rule of this section.

**A community-relay-list operator's identifier is non-transferable.** The operator's list entry carries the operator's P-256 public key, that key does not rotate, and an operator that changes its key takes a new list entry at the next release. A party verifying any object an operator signs reads the key from that operator's list entry and resolves no chain of the operator's own. KERI states the rule in one sentence under `spec-body` §Backer list: "When the Backers are Witnesses, then the AIDs themselves MUST be non-transferable, fully qualified public keys… Consequently, the Witness does not need a KEL because its key state is fixed and is given by its AID."

**The relay proof of control**, fields in preimage order: `operator` (32 bytes), `nonce` (32 bytes, echoed verbatim from the QUERY), `routing_id` (32 bytes), `value_digest` (32 bytes, `SHA-256` over the response's blob bytes under the repeated-field rule of §9.5.1), and `observed_at` (8 bytes, big-endian u64, the relay's own clock). Its signature preimage is

```
SHA-256("SCP-RELAY-PROOF-V1:" ‖ operator ‖ nonce ‖ routing_id ‖ value_digest ‖ observed_at)
```

Every field is fixed width, so the object is 136 preimage bytes and one 64-byte signature, 200 bytes in all.

The proof verifies under the attestation class of §9.7.1 and under no other class, so its signature verifies against the P-256 public key the operator's community-relay-list entry declares. A proof is a live challenge-response over a nonce the reader drew for one query, so it has no future version of itself to survive, and it carries no position field because a non-transferable operator key has no position to name.

A resolver counts a relay as a proven source only where five checks hold: the echoed nonce equals the one it sent, the routing id equals the one it queried, the value digest equals the same construction over the bytes received, `observed_at` sits within the clock-skew tolerance of its own clock, and the signature verifies against the P-256 public key that operator's community-relay-list entry declares. The nonce is what makes a proof unreplayable, because a proof over a static response would let one party present two once-genuine responses on its own network path.

A relay that serves no proof, or one that fails any of the five checks, counts as one unattributed source and can never be the second of two.

**A relying party's recognized set** is the list of operator identities whose cosigned heads that party reads as evidence. It is the party's own policy, held locally, it defaults to the community relay list, and it is never derived from any suffix's own key state, because a suffix's author chose what its key state names. KERI states the same under `spec-body` §Indirect exchange via witnesses and watchers: "the pool is under the ultimate control of the AID's event validator. To clarify, it is not under the control of the AID's controller".

**Head provenance.** How a party came to hold the head it adopted is a three-valued record named `HeadProvenance`, whose variants are `WitnessRead`, `TwoRelayRead`, and `SingleRelay`, and every SDK binding carries those names unchanged. The SDK records the value and surfaces it beside the standing. **No rule reads the record**, in this section or any other. A rule that withheld an act on the record would withhold that act on a property of the reading party's own network, and it would restore the missing-cosignature gate that Alec's watch-and-report ruling removed, under the name of a second source.

**Divergence.** Two chains diverge when they share a prefix and each carries, at the first position after that prefix, an event the other does not carry. The shared prefix is the longest common prefix, and a divergent suffix is the part of one chain after the shared prefix.

**The order of the key-event preimage's fields is fixed here and waits on nothing.** R13 defers the identifier's textual form and defers nothing else.

**The key-event preimage binds twelve fields in this order.**

1. `event_type`, one byte: `Inception` `0x01`, `KeyState` `0x02`, `CommitmentRollover` `0x03`, `RootRecovery` `0x04`. It comes first because a verifier derives the kind before it parses the fields that kind carries.
2. `identifier`, 32 bytes, all-zero in the inception event.
3. `sequence`, 8 bytes big-endian.
4. `predecessor_digest`, 32 bytes, all-zero in the inception event.
5. `standing_root`, one byte, `CoSigns` `0x01` or `Lost` `0x02`, on a `RootRecovery` alone.
6. The signer index list of each group the kind names, in the kind's own group order, each a 4-byte count then one byte per index.
7. The signature-form list of each of those groups, in the same order.
8. The revealed keys: a 4-byte count, then one 33-byte point per named reveal index.
9. The installed root set and its threshold: a 4-byte count, one 33-byte point per member, then a 4-byte threshold.
10. The key-state snapshot.
11. The key-event seals: a 4-byte count then one 32-byte digest each, on a `KeyState` alone.
12. The continuation: one byte, `0x00` for abandonment or `0x01` for a commitment list, and where `0x01` a 4-byte count, one 32-byte commitment per member, then a 4-byte next threshold.

**The key-state snapshot's own order** is: the 4-byte root threshold; the key list as a 4-byte count then one 45-byte entry per key the snapshot names; the next set as a 4-byte count then one 2-byte entry per member, `custody_type` then `key_algorithm`, in the order the key entry ends with; the witness set as a 4-byte count then each 32-byte operator identifier; the 4-byte witnessing interval; a one-byte service-key role discriminator; and the 32-byte delegator. Each 45-byte key entry is `key` (33-byte compressed point), `role` (one byte), `condition` (one byte: `current` `0x01`, `Superseded` `0x02`, `Retired` `0x03`, `Compromised` `0x04`), `compromised_from` (8 bytes, the position a `Compromised` entry carries and zero otherwise), `custody_type` (one byte), and `key_algorithm` (one byte), with root members in the root set's own list order, which is what makes a root signer index resolvable from the snapshot.

**Key role.** A key's role is a one-byte discriminator named `KeyRole`, whose two variant names are `RootMember` (`0x01`) and `Active` (`0x02`), carried by every key entry of a key-state snapshot. The snapshot's service-key role discriminator takes the same one-byte encoding and carries `Active` as its one registered value, because `#active` is the identity's one operational role. A verifier MUST reject any other value in either field. Every SDK binding carries the type name and both variant names unchanged.

**Why each binding is in the preimage.** Every signature an event carries is over one identical preimage. Without predecessor binding a root holder could copy the owner's genuine revealed `RootRecovery` bytes onto its own fork at the same sequence. Without the index list in the preimage a relay could strip one of several signatures with no detectable defect. Without the form list a relay could rewrite one slot's declared form and re-split the signature field into a second self-consistent parse. Without the continuation in the preimage a relay could strip the next commitment and substitute abandonment with every named signature still verifying.

**The name-binding criterion.** An enumeration this section defines is name-bound, meaning its type name and every variant name are identical in every SDK binding, where a binding surfaces it to callers or where it serializes on the wire. Without one criterion, four bindings inventing four names would register one later-added variant under four different names. Every other enumeration is not name-bound. Thirteen meet the criterion: `SignatureForm`, `KeyAlgorithm`, `CustodyType`, `CustodyProfile`, `KeyRole`, `StandingRootDeclaration`, `RecoveryHandle`, `RecoveryPhase`, `HeadProvenance`, `ContinuityStanding`, `ContentVerdict`, R3's four kind names, and R14's six verdict names.

#### The rules

**R1 — a commitment changes only under a reveal.** The standing commitment MUST change only in a reveal-authorized event, and a verifier MUST reject a chain in which the commitment changes at an event that reveals nothing. If a root signature alone could fix a commitment, an attacker holding the root would commit to keys it holds and the owner's later reveal would match nothing. KERI carries the same closure under `spec-body` §Message type field, where only an establishment event carries `n`.

**R2 — inception.** The inception event installs the first root set and threshold, fixes the first commitment list and next threshold, and carries the initial key state. Its root signature verifies against the root set the inception itself installs. A verifier MUST reject an inception event that fixes no commitment.

A verifier MUST recompute the identifier from the inception event and MUST reject a chain whose recomputed identifier differs from the identifier a relay served it under. Without that check a relay could serve any self-consistent chain, the attacker's own included, under any identifier. KERI requires the same match under `spec-body` §Inception event pre-rotation.

An identity is usable the moment its controller publishes its inception event: it resolves, derives a key state, and ranks against any fork from its first event forward, whether or not any witness has cosigned it.

**R3 — what a verifier rejects.** A verifier MUST derive an event's kind from the type discriminator in its preimage, never from which signatures the event carries, and MUST reject a chain carrying an event whose discriminator it does not recognize. Deriving the kind from the signatures present lets a copy-level strip change what a verifier thinks it is reading. The four kind names `Inception`, `KeyState`, `CommitmentRollover`, and `RootRecovery`, and the four condition names, are the protocol's identifiers and every SDK binding carries them unchanged. KERI carries the same field under `spec-body` §Message type field.

| Kind | Signature groups, in the event's group order | What it changes |
|---|---|---|
| `Inception` | A root signature by the installed root set | Installs the first root, carries the initial key state, fixes the first commitment |
| `KeyState` | A root signature by the standing root | Carries a complete key state and any seals; changes no root and no commitment |
| `CommitmentRollover` | A reveal, then a root signature by the standing root | Fixes the next commitment or declares abandonment; changes no root and carries no key state |
| `RootRecovery{CoSigns}` | A reveal, a root signature by the installed set K′, then a root signature by the standing root | Installs K′, carries the complete post-recovery key state, fixes the next commitment |
| `RootRecovery{Lost}` | A reveal, then a root signature by the installed set K′ | The same, without the standing root's signature |

**The signature layout is closed.** Each kind, and for a `RootRecovery` the kind together with its `standing_root` value, fixes which groups the event carries and in what order; the index list fixes the slot count and the form list fixes each slot's layout. Bytes past the last slot the form list accounts for are a copy-level defect, and so is a slot whose declared length prefix runs past the field or past its bound. Any relay can strip or stuff a signature the copy carries with no detectable defect, and an unbounded signature field is a verification-cost amplifier.

An event carries no signature that its kind, its index lists, and its form lists do not name. A third party's endorsement and a witness's cosignature are separate signed objects over the event's preimage digest, because evidence that rides the copy is neither reliably present nor reliably absent.

**`standing_root`.** A `RootRecovery` carries a required field `standing_root` with exactly two values, `CoSigns` and `Lost`, bound in the preimage. Its type name is `StandingRootDeclaration`, and every SDK binding carries that name and both variant names unchanged. The declaration, and not the presence of a signature, says which signatures the event names, so a `RootRecovery{CoSigns}` missing its root signature is a copy-level defect and never a `RootRecovery{Lost}`.

`Lost` is a controller obligation and no verifier checks it. The signing quorum MUST establish that fewer than t members of the standing root are reachable before it declares `Lost`, and where the SDK itself holds at least t members it MUST refuse, with a typed error, to sign `standing_root: Lost`. That refusal is the one mechanical realization, and it cannot run for an organization whose root members sit in separate substrates. Every relying party reads `Lost` as the controller's declaration and never as a checked fact.

A `RootRecovery` carries the revealed keys, the installed set K′ and its threshold with a root signature by K′ as proof of possession, the complete post-recovery key state, and the next commitment. No revealed key is ever installed, and no root member is ever the preimage of any commitment. Installing the revealed key as the new root made recovery work exactly once, because the live root was then the preimage of the consumed commitment.

Authorization is the signature by the revealed private keys and never the reveal alone, because a revealed public key is public the instant the event appears. KERI requires the same under `spec-body` §Rotation using pre-rotation, where a rotation "MUST be signed by a dual threshold-satisficing subset of the newly current set of private keys".

**Author-attributable defects.** A verifier rejects the chain at the event where any of these holds: a signer index list naming fewer indices than the indexed set's own threshold; a repeated index; an index naming no member of the set; a root set, next set, or commitment list whose entries are not pairwise distinct; a threshold outside the range one to the size of the set it indexes; a sequence that is not its predecessor's plus one; a revealed key whose commitment is not the standing list's member at the named index; a `KeyState` installing a root set or threshold differing from the standing root at its predecessor; a `CommitmentRollover` carrying a key state; a state-carrying event listing one public key more than once; an unrecognized key-algorithm value; a form list whose length differs from its index list, or naming an unrecognized form; an unrecognized discriminator; a next threshold lower than the threshold of the root standing after that event; a service-key designation naming a key that snapshot does not list `current`; a witnessing interval outside `MIN_WITNESSING_INTERVAL` and `MAX_WITNESSING_INTERVAL`; a witness set over `MAX_WITNESS_SET_SIZE` entries or not pairwise distinct; a snapshot identical to its predecessor's; a witness set naming the subject identifier itself; more than one key `current` in any operational role; a key installed that appeared earlier as a revealed next-set key; a commitment whose preimage is a key that same event installs; a nonzero delegator; and any violation of an R4 or R8 obligation.

**The two defect classes. The criterion is whether a keyless relay could have produced the defect.** A copy-level defect is one a relay holding no key could produce, so the verifier discards that copy, treats the position as unserved, and records nothing against the identity. An author-attributable defect is signed content, so the verifier rejects the chain at that event. The two lists above are indicators a verifier applies under that criterion.

**R4 — what a reveal-authorized event must do.** A reveal-authorized event either fixes the next commitment list and next threshold, or carries an explicit abandonment declaration and generates no next set. An event that does neither is invalid, because a chain whose standing commitment is consumed and neither replaced nor abandoned has no recovery path and no terminal state.

Only a `CommitmentRollover` co-signed by the standing root may declare abandonment, and a controller whose root is lost recovers first and abandons under a second reveal co-signed by K′. Abandonment on a reveal alone would let anyone who ever obtained enough of one next set kill a live identity whose root is intact.

Abandonment is terminal at the position of the abandoning rollover on the chain that carries it: no further key event on that chain is valid, and a verifier MUST reject any event whose predecessor chain contains one. The predicate is validity on a chain the verifier adopted, and not a threshold of witness cosignatures. KERI states the same under `spec-body` §Next key digest list field: "no more key events MUST be allowed in its KEL".

The abandoning controller owns the boundary. Before publishing the abandoning rollover it MUST issue the retirement Update in every context it belongs to, and each of those Commits is the abandonment boundary in its context. In a context the controller cannot reach there is no boundary, and that context's members keep verifying content under the abandoned identity's operational key until the controller reaches them. A fallback to that context's last Commit gave two rules opposite verdicts on one Commit history and retroactively invalidated content the identity signed while still a member.

After a relying party confirms an abandonment it MUST treat every UCAN the identity issued as revoked, every attestation as expired, and every sender key it holds as retired, and it MAY then remove the identity from a context and withdraw its standing.

A relying party MUST NOT act socially on a chain it adopted, for an adopted takeover or an abandonment, until it has confirmed that chain's head from a source the identity's service record does not name, because the holder of the designated key chose the relays that record names.

A public key is installed by at most one event on a chain and holds one role there, and listing an already-installed key in a later snapshot is not an installation.

**Commitment freshness.** A fixed commitment equals the commitment of no key a reveal on this chain has revealed, and of no key that same event installs. An unexposed member of the standing next set MAY be re-committed in the superseding list, so its commitment may repeat across several events. KERI's `spec-body` §Reserve Rotation holds a member unexposed across several establishment events and re-lists its digest in each. The danger a blanket rule addressed, a spent or stolen key satisfying a later reveal, reaches a revealed key and not an unexposed one.

**R5 — destruction.** After retaining the signed event, the controller MUST destroy every private key the reveal-authorized event revealed, from every custody location and backup medium it controls, and MUST NOT destroy them before that retention. A revealed key is public the instant the event appears, so a surviving copy lets whoever obtains it fork below the superseding event and reveal the same commitment. The duty binds revealed keys only: an unexposed member the superseding list re-commits is retained under §9.7.4.1 item 8, and one that list drops is destroyed with the revealed keys.

R5 reaches only the controller's own copies. A Shamir share held by a contact, a photographed mnemonic, and a cloud key store's historical snapshot sit outside its reach, so a controller using a non-destructible medium cannot fully comply and the SDK MUST warn that controller at custody selection.

**R6 — the root rule.** Where a verifier holds two valid chains that diverge from a shared prefix, it lets C be the standing commitment at the shared prefix, locates on each suffix the first event that reveals C, and ranks:

- **rank 1** where that event also carries a root signature verifying against the root standing at that event's predecessor;
- **rank 2** where that event carries no such root signature;
- **rank 3** where the suffix reveals nothing.

A lower rank number beats a higher one, and the winning chain supersedes the losing chain in its entirety. Alec ruled on 2026-09-07: "Root wins sounds like a good solution."

**The rank criterion is pinned.** Rank reads exactly two properties of a suffix and reads nothing else. A verifier reads the tier a root signature confers at the revealing event's predecessor and never at the event itself, which makes the tier a property the shared prefix fixed rather than one the claimant chose. At the event itself the standing root of a `RootRecovery` is the fresh set K′ that event installs, so every claimant would satisfy the test against its own key. Alec gave the reason on 2026-09-07: "If an attacker has the root, it's GG. What would you gain by trying to optimize against that case?"

**Rank is monotone.** Once a suffix carries a C-revealing event its rank is fixed and extending that suffix does not change it. A reveal consuming a commitment the suffix itself fixed confers no rank, because the shared prefix never committed to those keys; otherwise a party whose recovery installed its own root and commitment could reveal that commitment and claim rank 1.

A verifier MUST NOT decide a divergence by head sequence or by the first event after the shared prefix. Comparing that first event lets the forking party choose which events are compared, and comparing head sequences lets the party that appends the most events win. With more than two chains a verifier ranks every pair against that pair's own shared prefix, the winner wins every pairwise comparison, and the composite tie takes the class of the strictest pair. KERI treats `sn` as a location and never an arbiter, under `spec-body` §First Seen Policy.

**R7 — a tie.** Equal rank resolves no winner and the identity is contested. A tie at rank 1 is terminal by key material and proves both parties held enough of the next set and a threshold of the shared prefix's root. A tie at rank 2 is terminal and proves both held enough of the next set while neither could produce the root signature. A tie at rank 3 is pending, and a later reveal decides or escalates it. Ranks 1 and 2 are terminal for one reason: C is consumed on both suffixes, so no key event on either changes the comparison.

For a contested identity a verifier MUST return `Contested`, MUST NOT adopt any tied suffix as the `current` key state, and MUST retain every tied head and suffix as evidence. It uses the shared prefix's key state as the verification basis for content a context placed before the fork, verifies nothing after that, and MUST NOT serve that state as `current`. Where a party compromised the root before the fork point, the shared prefix already carries the attacker's events.

"Before the fork" in a context anchors to the member's own observation: content is before the fork where the member accepted it under an epoch no later than the last Commit that context observed from the identity before that member first observed any divergent suffix. A member that observed no such Commit reports `Invalid{no_prefork_basis}`. Anchoring to the fork position instead would name a Commit that exists only where the fork position happened to retire a key, and three members would read three different Commits for one message.

A rank-3 tie has a cheap exit: the controller signs a `CommitmentRollover` or a `RootRecovery{CoSigns}` on the suffix it keeps, which puts that suffix at rank 1. That exit spends the standing commitment, so R10's avoidance is cheaper. Terminal ties have no exit.

**No rule inside the log resolves a terminal tie.** Ordering two valid reveals of one commitment by first observation would divide relying parties by what each saw first, and ordering them by any field would let the second author read the first and match it. Every such rule removes recovery from an unforeseen compromise, because the owner's own recovery is the second reveal in exactly the case the owner needs it.

Recorded so a later author does not rediscover it: a double-authentication-preventing signature scheme with the pre-rotation key as the DAPS key produces no winner, because extracting the leaked secret proves a double reveal happened and never which party is the controller, and no admitted substrate produces a DAPS signature. It is a candidate for the evidence layer alone.

Where R6 later resolves a divergence a verifier recorded as a rank-3 tie, or that tie escalates, the verifier MUST retire the rank-3 equivocation record and MUST NOT count it against the identity, because the benign two-device race would otherwise block a pair until a human ceremony.

**R8 — deriving the key state.** A relying party derives the key state from the latest state-carrying event at or before the head of the chain it adopted. No earlier event contributes, and a verifier applies no diff, no undo, and no voiding, so a `RootRecovery` replaces the entire key state in one event. An attacker holding the root who appends `KeyState` events to the one genuine log produces no divergence, so R6 never runs and only a full replacement removes what that attacker installed.

A verifier derives every historical key's condition by replaying the log. A state-carrying event asserts only the condition changes it makes: its key list carries every key `current` at that position, and a `RootRecovery` additionally carries one entry per key whose condition it changes, `Compromised{from: N}` for each key it names, together with the fresh root set and the operational keys it installs. No event erases an earlier event, and a state-carrying event that changes a key's condition and omits that key is malformed.

A `Compromised{from: N}` entry carries a position N bounded by the sequence of the event that carries it, and a verifier MUST reject an entry whose N exceeds that. N has exactly one reader outside this section, the log-anchored evidence class of §9.7.1. No content rule reads N, and no rule in this section rejects a controller's event on account of content.

**R9 — storage, service, and retention.** A validating relay keeps one slot per pair of routing id and divergent suffix. Two prefix-related chains are one chain and collapse into the slot holding the longer; two divergent chains occupy two slots. A slot holds the full chain from the inception event to its head, and a relay serving a head serves every predecessor. Keying the slot on the root set alone would put every divergence that has not yet installed a new root into one slot and hand it to whoever published first, so no verifier would hold both chains and R6 would never run.

**The write rule.** A relay accepts a frame on one of two preconditions: its first event is an inception event that recomputes to the routing id's identifier, or its first event's predecessor digest names an event the relay already holds at that routing id. A relay rejects a frame meeting neither, and the publisher's remedy is to publish the intervening segments first, in order. Without that rule a root thief who inflated the chain past one frame made the victim's recovery unpublishable.

**Event identity.** An event is identified by its preimage digest, and every comparison reads that digest and never the bytes, so a party holding a valid event that receives a byte-different valid event with the same digest keeps the copy it holds. Under a byte comparison two encodings of one reveal-authorized event would be two suffixes revealing one commitment, both rank 1, and R7 would contest the identity terminally on a duplicate of its own signature. KERI identifies an event the same way, under `spec-body` §SAID fields.

**The three write outcomes.** For an accepted frame the relay compares each event's preimage digest against the event the slot holds at that position. Every digest matching inside the slot's range is an idempotent TTL refresh. Every held digest matching, with the frame continuing past the head, extends the slot. A first differing position makes the frame's events a second divergent suffix in its own slot.

**Serving order and the page walk.** A relay serves a slot's frames in ascending order of each segment's first sequence. The walk is over a routing id and not over one slot: a resolver re-issues QUERY with `since` set to the `stored_at` of the last frame it accepted at that routing id, takes every frame each page returns, and assembles frames into slots itself by predecessor digest. It stops where every slot it opened runs from inception to a head, or where a page returns no new frame. A resolver advancing `since` per slot would skip the frames of a second slot interleaved below its own high-water mark.

**The two further object kinds.** A verifier retains, per retained suffix, at most one cosigned head per witness the key state at that suffix's head names, and at most one conflict statement per pair of witness and retained suffix, keeping the highest `observed_at`. Both keys are that pair, so `MAX_WITNESS_SET_SIZE` and `MAX_RETAINED_SUFFIXES` bound each at 256 objects per identity. A key of witness and offered digest would need a constant of its own, because a party holding a threshold of the subject's root offers one witness any number of distinct divergent chains. Both objects are evidence a party may read and never an input to a verdict.

**Why a flood of slots takes no identity.** Every event a slot holds stands under a root the relay verified from the inception event forward, so a party that opens many slots has signed every one of them under a root it holds. Slot count confers nothing, because rank reads two properties and neither gets easier by publishing more forks.

**Segmentation.** A frame carries a contiguous segment of one chain, naming the segment's first and last sequence. A chain carries no ceiling on the keys it installs and none on its sequence, because a state-carrying event names only the keys that are current and the conditions it changes, so an event's size follows the identity's configuration and never the chain's length. A sequence ceiling would let a root thief pad the chain until the victim's recovery had nowhere to land.

**The retention bound.** A verifier retains at most `MAX_RETAINED_SUFFIXES` divergent suffixes per identity, and that count is the whole of the retention rule; no second bound refuses a suffix on arrival. A bound with no rank term is defeated by the cheapest suffix to manufacture, so a party filling a routing id with rank-3 bytes would deny the owner's rank-1 recovery its slot at every relay that had not already stored it.

**The eviction rank** is a scalar: the R6 rank the suffix carries against the chain it forked from, read against the commitment standing at that suffix's own fork position. Eviction reads that one term and nothing else, and R6's pairwise comparison decides adoption while no eviction reads it. A suffix is rank 1 in one pair and rank 2 in another, so "never evict a rank-1 suffix" had no referent and two relays evicted different slots from identical inputs.

**The eviction rule.** A candidate that would exceed the count bound is admitted wherever the retained set holds a suffix the verifier may evict, and the verifier evicts the retained suffix carrying the highest rank number, breaking a tie among equal ranks by evicting the suffix it observed most recently. Evicting the earliest-observed equal-rank suffix would evict the owner's own chain first at every verifier that had been following the identity. A rank-1 suffix is never evicted, so where every retained suffix is rank 1 the candidate is not admitted. Each eviction records the evicted head event's preimage digest.

**The rank-1 flood.** Where every retained suffix is rank 1 and another rank-1 candidate arrives, the verifier keeps the retained set and returns `Contested{…, residue: n}`, where n counts the rank-1 candidates it could not retain. A validating relay in that state rejects the further frame and records its head digest. A resolver MAY stop fetching once it holds two rank-1 suffixes.

**R10 — the controller's procedure.** The controller signs the row that matches its situation.

| The controller's situation | What it signs |
|---|---|
| Holds a threshold of its root and must retire it | `RootRecovery{CoSigns}` |
| Holds and trusts its root, and suspects only a copied pre-rotation key | `CommitmentRollover` |
| Has lost its root | `RootRecovery{Lost}` |
| Is retiring the identity and holds its root | `CommitmentRollover` declaring abandonment |
| Finds its identity contested and wishes to retire it | `RootRecovery{CoSigns}`, then abandonment under K′ |
| Finds its designated witnesses unreachable, silent, or refusing | `KeyState` naming a fresh witness set |

The SDK MUST treat any reveal-authorized event on its identity's chain it did not sign, and any root-signed event it did not author, as evidence of compromise, and MUST alert at maximum severity. It MUST be able to extend a suffix the controller authored even after its own verifier contested the identity, and where its own identity is contested it MUST tell the human the tie class the verdict carries. KERI directs a controller to watch its own witnesses under `spec-body` §Indirect exchange via witnesses and watchers: "Each validator MAY use its own watcher pool to watch its own witness pool of the AID that it itself controls in order to detect external attacks on its witnesses".

A controller's device about to publish an event at a sequence the chain already carries a different event at MUST discard its own event, fetch the chain, and re-sign its intended change on the head it finds, where its own event is not reveal-authorized. Where the pending event is reveal-authorized that obligation does not apply and the controller MUST NOT discard it, because a discarded reveal-authorized event would reveal the standing commitment a second time and contest the identity permanently.

A controller SHOULD roll over on suspicion and not on a schedule, because every rollover mints a spent key whose later leak contests the identity.

**Self-observation.** The SDK MUST fetch its own identity's log at a stated cadence, no less often than the witnessing interval the key state names and on every launch, from at least one relay in the fallback set, and MUST treat an inability to complete that check as an alert. That cadence is also the submission cadence of §9.7.4.3.

**Before composing a snapshot** the controller MUST hold its chain from the inception event, MUST diff the chain's witness set and service-key designation against a pre-compromise record, and MUST diff its service record's relay list against a pre-compromise copy. It refuses to sign on `Inconclusive`. On `Contested` it refuses only where it cannot identify which suffix it authored, because a blanket refusal would lock the controller out of the first row above, whose premise is a root-signed event another party wrote onto the chain.

**The device boundary.** A reveal-authorized event MUST be produced on a device, and its successor keys generated in custody, that the controller has established the asserted compromise did not reach. For exportable custody the boundary is a fresh platform account with no state restored from the compromised one. For a non-exportable root the boundary is a fresh operational keychain on a device the compromise did not reach, and the recovery signs where the root and pre-rotation credentials reside, because a fresh platform account cannot be the boundary for a credential that does not move to it. The successor next set for a passkey-root controller is by default a second passkey in the same platform account, with a FIDO2 security token or a second platform account offered, and it is never the device's operational keychain.

A controller that cannot establish the boundary MUST NOT proceed, and on the non-exportable arm it MUST NOT sign until it has regained exclusive control of the platform account holding the root and pre-rotation credentials. Before the reveal signs, it MUST confirm the commitment list, the next threshold, the K′ set and root threshold, and whether the event declares abandonment, on a device with a display that is not the assembling device, or by comparing a displayed digest against one the pre-rotation substrate computes. That confirmation binds the bytes the signing substrate consumes to the event the human read, and establishes nothing about where the committed successor keys came from.

**Ceremony order.** Enumerate; generate the next set under §9.7.4.1 items 1, 3a, 4, and 5b through 5d; for a `RootRecovery` generate K′ and the operational keys under the device boundary; for an abandoning rollover issue the retirement Update in every context; persist the recovery handle carrying the composed preimage; sign; publish; retain; destroy. The persist precedes the signature, because a controller that crashed between signing and persisting would resume by composing a fresh next set, and its second event would reveal the standing commitment a second time.

The controller MUST durably retain the signed event byte for byte before it destroys the spent keys. Confirmed publication is durable self-retention together with acceptance by at least one relay in the fallback set, the ceremony completes at confirmed publication plus destruction, and witness submission gates neither.

The SDK MUST refuse, with a typed error, to compose a reveal-authorized event where it can reach no source in the fallback set, because a controller that cannot read its own chain from a source an attacker did not choose cannot establish what it is recovering from.

**The recovery handle** is one enum named `RecoveryHandle` whose variants are `FixesCommitment` and `Abandons`, each carrying a `RecoveryPhase` and the fields its resume consumes. The continuation is the variant tag so that `Abandons` has no next-set field by construction. `RecoveryPhase`'s five values are `Composed`, `Signed`, `PublishSent`, `Confirmed`, and `Submitted`. Every SDK binding carries both type names and all seven variant names unchanged. Exactly one accessor, `load_pending_recovery`, loads a pending handle, and exactly one entry point, `resume_recovery`, consumes it by value.

**Abort** is a third entry point named `abort_recovery`, available at `Composed` alone and in no phase after the signature. The boundary abort respects is the signature and not the publish, because the signature is the authorizing act: a software zeroize of a signed event is not verifiable, and a surfaced copy beside a recomposed one is two reveals of one commitment and a permanent self-contest. The remedy for a wrong device-boundary establishment discovered after signing is to publish the signed event and sign a further reveal-authorized event under the commitment it fixed.

**R11 — classifying a candidate head.** A candidate head is on the accepted chain where either chain is a prefix of the other, divergent where the verifier holds both chains back to a common ancestor and they diverge, and inconclusive otherwise. On inconclusive the verifier holds its baseline, records nothing, and returns `Inconclusive{MissingEvents{range, failed_sources}}`, having tried at least one relay in the fallback set.

**The first-contact floor.** A verifier holding no accepted baseline MUST obtain the chain from at least two entries of the community relay list under distinct declared operators, each serving a relay proof of control the verifier checked. Two entries under one operator identity count once, and a relay outside the list counts toward neither number. A single relay can always serve a genuine prefix truncated before the event the reader most needs, which forks nothing, verifies clean, and faces a verifier holding no baseline.

Every degree below the floor is fail-closed: the verdict is `Inconclusive{SingleSource}` and the verifier adopts no head. The degrees are reaching no second relay, reaching two relays that prove one operator identity, holding a fallback set with fewer than two entries under distinct declared operators, and rejecting every proof on the resolver's own clock. The clock-skew degree is counted separately so a party tells its own clock from a network failure. A fresher head does not relax the floor.

A verifier MUST record equivocation evidence only from two chains it holds in full back to their common ancestor, and only where R6 resolves them as a tie. A single relay that withholds linking events, or serves a mutilated copy, could otherwise cause a durable verdict against an honest identity. KERI likewise requires holding both versions before a party calls an event duplicitous, in its terms and definitions entry for duplicity.

**R12 — the stored baseline.** For a candidate head on the accepted chain a verifier discards a head at a strictly lower sequence, changing no stored state and returning `Discarded{accepted_head}`; an equal sequence with an identical head returns `Confirmed`. A divergent candidate's head sequence decides nothing. Routing a stale candidate to the success branch let an attacker who suppressed the newest head and served a genuine older one pin verifiers to a pre-rotation key state without inducing any failure.

The stored baseline is the head of the chain the verifier adopted. Adopting an R6 winner MAY lower the accepted head sequence, and a verifier's stored baseline MUST be able to express that decrease, because a monotone maximum cannot record the adoption of a lower-sequence winner.

**R13 — separators, the identifier, and the routing derivations.** The key-event signature preimage uses `"SCP-KEL-EVENT-V1:"`; the pre-rotation commitment uses `"SCP-PREROTATION-COMMITMENT-V1:"`; the key-event seal uses `"SCP-KEL-SEAL-V1:"`; and the witness layer's two objects use `"SCP-COSIGNED-HEAD-V1:"` and `"SCP-WITNESS-CONFLICT-V1:"`. All five are registered in the domain-separator registry of §9.18.2, beside the identifier's own separator below. Registration in one table, rather than distinctness maintained by inspection, is what keeps separators collision-free as the table grows. `"SCP-MIGRATION-V1:"` is registered as retired, because the key-event-log model produces no migration proof.

The identifier is `SHA-256("SCP-KEL-ID-V1:" ‖ inception_signed_preimage)`, where the inception preimage carries its identifier and predecessor-digest fields as the all-zero placeholder. A verifier recomputes it under R2. The identifier separator is distinct from the event separator so that no signature preimage's digest is ever an identifier.

The routing derivations are `routing_id = SHA-256("scp:did:" ‖ identifier_bytes)` over the identifier's 32 raw digest bytes, with `SHA-256("scp:wit:" ‖ identifier_bytes)` for cosigned heads, `SHA-256("scp:wcf:" ‖ identifier_bytes)` for conflict statements, and `SHA-256("scp:svc:" ‖ identifier_bytes)` for the service record. The address is the type discriminant. Each derivation consumes the digest and never a textual encoding, so all four are fixed now.

**The one deferral.** The identifier's textual form is a display and URL concern a later revision fixes. Alec set the sequencing on 2026-09-03: "one thing at a time but all things in time." Because that form is unfixed, no example anywhere in the corpus prints an identifier: an illustrative body writes `<scp-identifier:name>`, and a field whose encoding is this deferral writes `<the … identifier, in the textual form 09 §9.7.4.2 R13 defers>`.

Every derivation the protocol performs consumes the 32-byte digest, so the four routing derivations above and both continuity-fingerprint forms of §9.11 are settled. What waits is display, URLs, and every signed structure that takes an identifier as UTF-8 bytes, which §9.5.2 enumerates where it states this deferral, so a reader does not take those preimages as computable.

**R14 — the verdicts.** A resolution returns exactly one of six, and every SDK binding carries the six names unchanged: `Confirmed`; `Adopted{head, baseline_decreased}`; `Contested{tie, heads, shared_prefix_head, fork_position, residue}`; `Inconclusive{cause}` with three causes, `MissingEvents{range, failed_sources}`, `CopyDefect{at_event}`, and `SingleSource{reached_sources, proven_sources, clock_skew_rejected}`; `Invalid{at_event}`; and `Discarded{accepted_head}`. A discard is a verdict so that a consumer routes it, because the resolution delivered nothing newer than the baseline. Holding no cosigned head is not a cause here.

`Invalid{at_event}` is the only cause of a resolution verdict named `Invalid`, and a copy-level defect never produces it. A second result type, `ContentVerdict`, is what content verification returns; its variants are `Valid`, `Unverified{reason}`, and `Invalid{cause}`, whose two causes are `no_prefork_basis` and `no_boundary`. Every SDK binding carries that type name and every variant name unchanged. Those two `Invalid` payloads are verdicts about one artifact inside one context and never about a chain.

The contested verdict, the retained suffixes it rests on, and the accepted-head baseline MUST survive the verifier's restart, and a verifier MUST persist them before it acts on any verdict. A persist failure returns an error and not the verdict. A resolver that published an adopted head, acted on it, and then died would restore a stale head and re-open the rollback the first-contact floor closes.

#### Worked examples

Each example traces one row of the failure-mode table of §9.7.4.1 and states the order of the parties' acts. That table carries every outcome and no example restates one.

1. **A root thief forks early against a controller whose root is gone.** The thief forks below the controller's last event and signs a `RootRecovery{CoSigns}` there under the root it stole; the controller, holding no root, signs `RootRecovery{Lost}` on its own suffix.
2. **A copied pre-rotation key against an intact trusted root.** The copy holder reveals the standing commitment on a fork below the event that spent it; the controller's own revealing event carried the standing root's signature.
3. **Two root-only suffixes.** Two of the controller's devices each append a root-signed `KeyState` at one sequence, and neither suffix reveals the standing commitment.
4. **A backup of a spent key reaches the root thief.** The thief holds the root and a copy of a key a past reveal spent, and reveals that same commitment on a fork below the event that spent it.
5. **An identity whose witnesses go silent.** The controller's designated witnesses stop answering, and the controller signs a `KeyState` naming a fresh witness set while the identity resolves and ranks throughout.
6. **A witness that cosigns two divergent heads.** One witness releases two cosigned heads carrying one `witness` value, one `subject` value, one non-zero `previous_cosigned_digest`, and two different `event_digest` values, which is the fault proof §9.7.4.3 defines.

### 9.7.4.3 Witness and Watcher Layer (Layer B)

**A witness watches and reports and decides nothing.** It runs one check, signs or refuses, and never adjudicates between two chains, and §9.7.4.2's definitions state that neither object it produces enters any rule of that section. Alec ruled the layer's scope on 2026-09-10: "watch and report as well". His reason: the residual the earlier required-witnessing model rested on, a lost root together with a leaked copy of a spent pre-rotation key, is removed for a default-profile user who keeps the default passkey custody of §9.7.4.1. He ruled knowing the asymmetry: moving from required to watch-and-report later is a relaxation, and the reverse is a flag day.

That earlier required model, under which threshold cosignatures conditioned an event's acceptability, was the orchestrator's design call and not Alec's. He asked on 2026-09-08, "So root, witness required, witness decides?", the orchestrator answered "root decides, witnesses required, witnesses never decide", and he did not confirm the "required" half in his own words. He stated the general correction on 2026-09-06: "I said B because you presented as an option that solves the problem not because it was something specific that I wanted. You gave me some options. I chose one."

**The cosigned head**, fields in preimage order: `witness` (32 bytes), `subject` (32), `sequence` (8, big-endian), `event_digest` (32), `previous_cosigned_digest` (32, never zero), `observed_at` (8, big-endian). Its signature preimage is

```
SHA-256("SCP-COSIGNED-HEAD-V1:" ‖ witness ‖ subject ‖ sequence ‖ event_digest ‖ previous_cosigned_digest ‖ observed_at)
```

signed by the P-256 key the witness operator's community-relay-list entry declares, giving 144 preimage bytes and one 64-byte signature, 208 bytes in all. It names no position in the witness's own key state, because a non-transferable operator key has no position to name.

The cosigned head covers the key-event log alone and says nothing about the identity's service record, because covering that record would give a witness a second thing to check.

One cosignature covers every event at or below the head it names, because each key event's preimage binds its predecessor's digest. KERI's backward hash-chained log gives the same property, under `spec-body` §Tetrad bindings.

**The one check.** Before it cosigns, a witness looks up the head it last cosigned for this subject, and the chain it is asked to cosign MUST carry that exact event digest at that exact sequence.

- Where the chain carries it, the witness cosigns.
- Where the chain ends below that sequence and matches everywhere it reaches, the chain is a proper prefix, so the witness refuses, names staleness, answers with its last-cosigned head, and emits no conflict statement.
- Where the chain reaches that sequence carrying a different event, the witness refuses and emits a conflict statement.

Two witness rewrites failed at the sentence that let a witness say yes to a non-extension, and a witness that adjudicates hands an identity to one key. The check is unconditional and carries no carve-out, including for a chain that supersedes the last-cosigned chain through a reveal-authorized event: at a witness a genuine recovery and a theft of a spent pre-rotation key are the same object, and a witness holds no evidence that separates them.

Two preconditions sit under the check and neither is a second judgement: the witness verifies the chain exactly as any relying party does, and it refuses a subject whose key state at the head does not name it. Its `observed_at` MUST exceed that of its last cosigned head and MUST sit no further ahead of its own clock than the skew tolerance. A witness whose stored `observed_at` exceeds its own clock past that tolerance keeps the record, refuses, reports the condition, and does not re-seed, because a party that moved that host's clock forward and back could otherwise make a chosen witness discard the one value its check reads.

**Durable per-subject state.** A witness retains, per subject it has ever cosigned, the subject identifier, the sequence and event digest of its last cosigned head, that cosigned head's preimage digest, and its `observed_at`. Each record is about 112 bytes and a witness holds at most `MAX_SUBJECTS_PER_WITNESS`. The witness persists the record durably before it releases the cosignature that record accounts for, because a witness cosigning on a cold baseline could sign both sides of a fork with no malice.

**Seeding, case 1.** A newly designated witness verifies the offered chain from the inception event, locates the latest state-carrying event at or before the offered head whose key state names it, and seeds at that event's sequence and preimage digest. It reads no cosigned head, its own or anyone's, and the first cosigned head it releases carries that event's digest as its `previous_cosigned_digest`. Seeding at the first such event instead would put a re-designated witness's floor at the event that first named it, which a recovery's suffix and a thief's suffix both carry, so the recovery would reach no fresh floor.

**Seeding, case 2.** A witness that lost its store re-seeds from its own previously published cosigned heads, keeping only those whose `witness` field is itself and whose signature verifies under the P-256 key its own community-relay-list entry declares, and seeding from the highest-sequence one. It counts no other witness's head, at any sequence and any age. Finding none of its own, it takes case 1.

A recovery reaches a fresh witness set: the recovery event is the latest event designating them, it sits on the recovered suffix, and the outgoing witnesses' heads sit on a suffix the recovery does not carry, so they enter no fresh witness's floor. A party holding a spent pre-rotation key takes the same path, and neither set's signatures decide anything.

**The conflict statement**, fields in preimage order: `witness` (32 bytes), `subject` (32), `held_sequence` (8), `held_digest` (32), `offered_sequence` (8), `offered_digest` (32), `observed_at` (8), under the separator `"SCP-WITNESS-CONFLICT-V1:"` and signed by the key a cosigned head is signed by, giving 152 preimage bytes and one 64-byte signature, 216 bytes in all. A refusal producing no object would leave the fork attempt as the witness's private knowledge. It names no position in the witness's own key state, for the reason the cosigned head names none.

A conflict statement is portable evidence that two chains for one subject were offered to one named witness, and it is not a verdict: the witness makes no claim about which chain the controller authored, and a party holding it applies R6 and R7 to the chains themselves. KERI splits the same three roles under `spec-body` §Indirect exchange via witnesses and watchers, where a Juror records evidence, a Judge evaluates it, and the validator decides.

**The fault proof** is two cosigned heads carrying one `witness` value, one `subject` value, one non-zero `previous_cosigned_digest` value, and two different `event_digest` values, which together prove the witness released two successors of one baseline. Two heads for two subjects share no baseline, and the never-zero field keeps a witness's first head after a seed from colliding with anything. The proof is portable and self-contained against the shipped list, because verifying either signature takes the P-256 key the witness's community-relay-list entry declares. It decides the operator's conduct and never the fork.

One party would act on the fault proof, and this spec names no such party. The community relay list is curated outside the protocol, and nothing in the protocol detects a curation breach. An SDK MUST surface the fault proofs it holds.

A badly curated list, or several entries secretly under one operator, is a supply-chain risk no protocol check covers, of the class a compromised browser root store belongs to.

**What a relying party reads a cosignature for.** Two cosigned heads for one subject where neither extends the other, or a conflict statement, tell a party that a fork exists, and what that party does with it is R6 and R7 on the chains themselves. A cosigned head also tells its holder how recently a recognized operator served this chain, which the SDK records and surfaces and no rule reads. KERI's `spec-body` §Indirect exchange via witnesses and watchers has a validator trust absent evidence of duplicity and withhold trust in its presence; the freshness reading is SCP's and that citation does not reach it.

A cosignature from an operator the running SDK does not list is not an error, so a release boundary changes what evidence a party holds and changes no verdict it reaches. A cosignature proves control of its declared operator identity by construction, because producing one requires the private half of the key that operator's list entry declares.

**Admission and eviction.** A witness admits a subject when that subject's key state first designates it, in arrival order, to `MAX_SUBJECTS_PER_WITNESS` subjects. It MAY evict a subject only where the key state at the head of the chain that subject last offered it no longer names it, and it evicts on no other condition. Silence is not an eviction condition, because a witness that evicted a quiet subject would seed it afresh on its return, and a party that suppressed a subject's submissions would then choose when that witness's floor resets. A witness at capacity refuses and names capacity as the reason.

**Who offers a chain.** One party offers a witness a chain: the subject's own controller, through the SDK, on the self-observation cadence of §9.7.4.2 R10, re-submitting until a cosigned head returns. A witness fetches nothing on its own account and cosigns nothing it was not offered. KERI assigns the same duty in KID0010 §Witnessing Policy: "the controller of a given identifier creates and disseminates associated key event messages to the set of N witnesses".

The SDK's default witness set for a new identity is the entries of the community relay list under distinct declared operators, capped at `MAX_WITNESS_SET_SIZE`, at `DEFAULT_WITNESSING_INTERVAL`. Identity creation completes at publication and waits on no witness.

The SDK MUST warn a controller that replaces the default set with unlisted operators or designates no witness, and MUST state the consequence in these terms: the identity's freshness then rests on that peer's own relay reads. The warning MUST NOT say that such an identity is unresolvable, unadmittable, or held at `Unresolved`. What the controller gives up is portability.

**What this layer does not cover**, stated rather than implied. The one check gives no evidence at or above a witness's last cosigned head, so two events at one sequence each extending that head record a race rather than a wrong. The witness's durable store is a correctness dependency on infrastructure the protocol does not control, and a witness restored from an older backup cosigns from the sequence that backup recorded. No rule bounds the rate at which one party designates witnesses, so a party minting identities in bulk drives every operator to capacity and holds those slots; a sound rate limit would have to bound designations per designating party without pricing the act and without reading any field an inception event's author chooses.

## 9.8 Message Security

This section specifies how SCP prevents message forgery, replay attacks, and ordering manipulation.

### 9.8.1 Envelope Integrity (Two Independent Checks)

Every SCP message has two independent integrity verifications, both inside the encrypted payload. Neither is verifiable by relays — relays see only opaque blobs.

**Inner check 1 — the P-256 identity signature.** The sender signs the payload with their Active Signing Key (`#active`). The signature is over a domain-separated, length-prefixed canonical hash: `SHA256("SCP-INNER-ENVELOPE-V1:" || version || message_type || len(context_id) || context_id || len(sender_did) || sender_did || epoch || generation || sequence || timestamp || len(payload_hash) || payload_hash || len(provenance_hash) || provenance_hash || len(signing_key_id) || signing_key_id)` where `payload_hash` covers the original plaintext (before padding), `provenance_hash` covers serialized provenance metadata, and an absent value is written `00 00 00 20` followed by the 32 bytes `SHA-256(0x00)`, which is what `len(provenance_hash) || provenance_hash` yields under §9.5.1's optional-field rule for a length-prefixed field, and `signing_key_id` is the verification-method fragment the sender signed under, `#active`. Because `signing_key_id` is inside the signed preimage, a tampered or forged verification-method claim invalidates the signature: the verifier resolves the public key for the *declared* `signing_key_id` under §9.7.1's content-class fragment lookup, and the signature can only verify if that method's private key actually signed — so a claim naming a method that did not sign fails verification. Including `version` and `message_type` (a discriminator byte) prevents downgrade and type-flipping attacks. Processing order: hash plaintext -> hash provenance -> sign -> pad -> sender-key encrypt -> MLS encrypt. Reverse on receipt: MLS decrypt -> sender-key decrypt -> strip padding -> resolve sender VM key by `signing_key_id` -> verify signature -> verify payload_hash -> verify provenance_hash. A failed signature means the envelope was tampered with or forged and MUST be rejected. **A verifier MUST reject an envelope whose `epoch` field differs from the MLS epoch that decrypted it.** The sender signs the `epoch` field, so a compromised key's holder could otherwise set it to any value; §9.7.1 orders content against a key's compromise boundary by the decryption epoch, and this check is what keeps the signed field from contradicting it.

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

**Message forgery:** Prevented by the P-256 inner signature + MLS membership_tag. Both checks are inside the encrypted payload (§9.8.1). An attacker who does not hold a member's private key cannot produce a valid inner envelope, and an attacker without MLS epoch secrets cannot produce a valid membership_tag.

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

**A relay that witnesses is accountable, not trusted, and the untrusted-relay invariant holds over it unchanged.** A relay an identity designates in its key state cosigns that identity's log head (§9.7.4.3), and every relying party verifies that cosignature itself against the operator's own key-event log rather than taking the relay's word for anything. A witness that cosigns two divergent heads is proven to have done so by the two objects it signed, so its departure from the one check is attributable to it by name and it says nothing about which of the two chains is authoritative. A witness supplies no confidentiality property, reads no encrypted content, and decides nothing about which chain a controller authored; what it supplies is one signed observation of what it held and when.

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

- **Forge messages.** Requires the sender's private key (for the inner P-256 signature, §9.8.1) and MLS epoch secrets (for the membership_tag).
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
  signature:    P256Signature   // 64 raw bytes, signed by the sender's #active key
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
  signature:            P256Signature        // 64 raw bytes, signed by the detector's #active key
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
context_seed  = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")
scalar_input  = HKDF-Expand-SHA256(context_seed, "SCP-PSEUDONYM-P256-V1", 48)
d             = (int(scalar_input) mod (n - 1)) + 1     // n = the P-256 group order
context_keypair = P256_keypair_from_scalar(d)
context_pseudonym = context_keypair.public_key           // 33-byte SEC1 compressed point
pseudonym_routing_id = SHA-256("scp-pseudonym-routing-v1:" || context_pseudonym)   // 32 bytes
```

**The routing id and the pseudonym public key are two values and this states which one travels on the wire.** `context_pseudonym` is a 33-byte point, and `pseudonym_routing_id` is the 32-byte digest above; **every routing field carries the routing id**, which is what keeps the routing-id space uniformly 32 bytes beside `context_routing_id` and `broadcast_routing_id`. The `pseudonym` field of the `PseudonymAnnouncement` (§25.19 Vector 36) is that routing id, so the announcement's reserved-value comparisons — against `[0;32]`, against `context_routing_id(ctx)`, and against `broadcast_routing_id(ctx)` — compare values of one width. `"scp-pseudonym-routing-v1:"` is registered in §9.18.2. The pseudonym public key itself stays inside the derivation and inside the pseudonym-to-DID mapping members verify on first encounter.

Here `identity_key_material` is the 32-byte `pseudonym_secret` (NOT the public key) defined in §9.10.4.A — a value that is not publicly derivable. **The seed-to-scalar step is the extra-random-bits method of FIPS 186-5 Appendix A.2.1**, and this spec states it in full because P-256 has no single canonical seed expansion of the kind RFC 8032 fixes for its own curve: expand the seed to 48 bytes with HKDF-Expand-SHA256 under the domain string above, read those bytes as a big-endian integer, reduce it modulo `n − 1`, and add one, which yields a private scalar in `[1, n − 1]` whose bias from uniform is below 2^-128 because the input carries 128 bits more than the group order. Implementations MUST NOT reduce the 32-byte `context_seed` directly, which would bias the low-order scalars, and MUST NOT reject-and-retry, which would make the derivation non-deterministic across implementations that draw retries differently. This single interpretation is what makes software pseudonyms agree byte-for-byte across platforms (see §25.19 for known-answer vectors).

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

**Threat: publicly derivable pseudonyms enable membership enumeration.** If `identity_key_material` in the HMAC were the raw P-256 public key bytes (which are public by definition), any party knowing a `context_id` and a DID's public key could compute `HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")` and test whether the resulting pseudonym appears as an active subscription on a relay. This constitutes a membership enumeration oracle.

**Mitigation: pseudonym secret.** The `identity_key_material` used in pseudonym derivation MUST be a 32-byte symmetric secret that is NOT publicly derivable. The pseudonym secret is generated alongside the identity keypair and stored within the custody boundary:

```
pseudonym_secret = HKDF-SHA256(
  ikm  = p256_private_scalar,   // the 32-byte P-256 private scalar
  salt = "scp-pseudonym-secret-v1",
  info = "",
  len  = 32
)
```

For **software custody**, the pseudonym secret is derived from the P-256 private scalar during key generation and cached in the `KeyCustody` store. The private key bytes are the only input — the public key is never used.

For **hardware custody** (Secure Enclave, Android Keystore TEE, HSM), where private key bytes cannot be exported, the `pseudonym_secret` is a **device-local** value computed inside the hardware boundary. It is an associated 32-byte symmetric key generated during `generate_keypair` and stored within the secure boundary, on every hardware substrate. **It is never derived from a signature that substrate produces**: §9.5 admits a hardware signer drawing its own nonce, so one message under one such key yields a different accepted signature on every call, and a signature-derived secret would give the same identity a different routing id on every launch. The hardware computes the HMAC internally using this device-local secret.

**Stance — software is cross-platform deterministic; hardware is device-local by design:** Software custody derives the `pseudonym_secret` deterministically from the private seed, so the same identity seed and `context_id` produce identical pseudonyms on every platform (Rust, Swift, Kotlin, TypeScript). This is a designed property and is pinned by known-answer vectors (§25.19). Hardware custody is **device-local by design**: the identity key never leaves the device, so its `pseudonym_secret` — and therefore its per-context pseudonyms — are bound to that device and are intentionally NOT identical across devices. Cross-device pseudonym identity is not a requirement of the protocol; a participant who moves to a new device uses the social/device recovery protocol (§3.3), which provisions a fresh identity (and thus a fresh device-local `pseudonym_secret`) at the destination. This is not a limitation worked around — it is the direct consequence of hardware keys being non-exportable, which is the security property hardware custody exists to provide.

**Interim — the ADR-057 in-browser client keys its pseudonym on the per-context MLS key, not the identity key:** The in-browser participant client (ADR-057, "A1 as-built" amendment) runs this SAME derivation *algorithm* (same domain separators, HKDF/HMAC recipe, and the FIPS 186-5 Appendix A.2.1 seed-to-scalar step §9.10.4 states — byte-identical to native, pinned by the §25.19 cross-target KAT), but keys it on the **per-context MLS `SignatureKeyPair`** the browser holds in wasm rather than the DID **identity** key — because in that slice the identity key is not reachable inside wasm (only the MLS key is). Consequently the browser's per-context pseudonym does **not** byte-match a native member's identity-keyed pseudonym for the same human/context. This is a **device-local pseudonym** in exactly the sense above: each member **announces its own** per-context routing id and peers **record** it from the authenticated announcement (§9.10.4 pseudonym announcements), so no member ever *recomputes* a peer's pseudonym and cross-device byte-parity is **not a routing requirement**. It is a knowing, human-ruled interim deviation from this section's identity-key source, and it resolves with #1980 (when the identity key becomes reachable by the browser, the derivation moves onto it, restoring the identity-key source and native↔browser byte-parity for the same human). See ADR-057 "Amendment (2026-07-16 — Option A)", the A1 as-built note.

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
context_seed_v2 = HMAC-SHA256(pseudonym_secret, context_id || epoch_BE || "scp-pseudonym-v2")
context_keypair_v2 = P256_keypair_from_scalar(seed_to_scalar(context_seed_v2))
```

where `epoch_BE` is a 64-bit big-endian pseudonym rotation epoch (distinct from MLS epochs), the HMAC key is the 32-byte `pseudonym_secret` §9.10.4 defines and never a public value, and `seed_to_scalar` is the step §9.10.4 states — HKDF-Expand-SHA256 over the seed to 48 bytes, reduced modulo `n − 1`, plus one — which this section cites and does not restate. Reducing the 32-byte seed directly is the reading §9.10.4 forbids.

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
2. **A first contact spreads its two queries across two operators.** R11's floor (§9.7.4.2) sends the two queries to community relays under distinct declared operators, so no operator observes a whole first contact.
3. **Aggressive caching:** 24-hour refresh for active contacts, 7-day for inactive. A resolver detects a stale chain by comparing the served head's sequence against the accepted head (§9.7.4.2 R12). Key change alerts trigger immediate re-resolution.
4. **No batch/prefetch, no resolution proxy.** Caching plus the spread across relays gives practical privacy without new infrastructure.
5. **Residual: a relay in the fallback set sees first contacts it serves no traffic for.** A community relay that stores no chain of its own still learns which `routing_id` a resolver IP asked for. A resolver that requires IP anonymity uses a VPN or Tor at the transport layer, the same control §9.10.11 names for message traffic.

### 9.10.8 Relay Query Privacy

1. **Per-context pseudonyms (§9.10.4) are the foundation.** Relay cannot link subscriptions across contexts.
2. **Relay set partitioning, mandatory.** Each context SHOULD use different relays from the client's other contexts. SDK distributes contexts across relays to minimize overlap.

**Combined effect:** Relay sees pseudonyms (unlinkable to identity) on a relay hosting only a fraction of the client's total context set. Per-context pseudonyms prevent cross-context linkage; relay partitioning limits the fraction of a client's activity visible to any single relay.

**Rejected alternatives:** Subscription mixing (subscribing to decoy routing IDs alongside real ones) was considered and rejected — decoy routing IDs receive zero traffic, making them trivially distinguishable from real subscriptions. Private Information Retrieval (PIR) was considered and rejected — computational overhead is disproportionate to the privacy gain given that pseudonyms and partitioning already prevent the relay from linking subscriptions to identities or contexts.

### 9.10.9 Cross-Context Key Isolation

Each SCP context is a separate MLS group with independent key material. Compromising one context's keys reveals nothing about any other context's keys. The identity key (P-256) is shared across contexts but signs actions — it never directly encrypts group content. MLS handles group encryption with ephemeral key material derived independently per group. Per-context pseudonyms (§9.10.4) prevent the identity key from being visible outside encrypted payloads.

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

The **key-event record frame** is the unencrypted counterpart to the §9.10.2 Minimal Outer Envelope: where the outer envelope is *confidential by encryption*, a key-event record is *self-certifying through the key-event log it carries* (§9.6.1). The frame is named for what it carries: a segment of the key-event log, never a DID document, which ADR-063 defers and this protocol does not produce. It is specified in §9.10 because that is where relay-stored record formats live. This design is issue #482. (§9.18.11 fixes the shared relay blob-size and blob-TTL bounds this frame reuses.)

The frame is **minimal and identity-specific — there is no magic tag and no record-kind byte.** Key-event records live at their own `routing_id` domain (`SHA-256("scp:did:" || identifier_bytes)`, §9.7.4.2 R13), so the address is the type discriminant; a frame needs no self-describing tag to say what it is. (A future MLS KeyPackage relay record, if built — issue #2202 — would define its OWN minimal frame at its OWN `routing_id` domain; key-event records and KeyPackages do NOT share a tagged multi-kind envelope family, and this frame introduces no such taxonomy.)

**Storage model — a raw relay blob.** A key-event record is stored as a **raw relay blob** at its routing ID, never wrapped in an `OuterEnvelope` and never MLS-encrypted: its authenticity comes from the key-event log its `value` carries (§9.6.1). Publication and resolution use the existing PUBLISH/QUERY operations (ADR-004), and this frame introduces no wire type of its own. `ClientMessage::Publish { routing_id, blob_ttl, blob }` writes the frame bytes, and `RelayMessage::Blob { …, blob }` returns them.

**Two fields carry the relay proof of control, and they are the one wire change this section makes to ADR-004's QUERY and Blob.** `ClientMessage::Query` carries an optional `proof_nonce: [u8; 32]`, which a resolver sets to 32 bytes it drew freshly for that query and to nothing else, and which `03-identity.md` §3.10.4 step 2 makes REQUIRED on a first contact. `RelayMessage::Blob` carries an optional `relay_proof: [u8; 200]`, the object §9.7.4.2's definitions state, and a relay that received a `proof_nonce` and can sign under the operator identity its community-relay-list entry declares MUST return one. Both fields are optional on the wire because a relay outside that list declares no operator and has nothing to prove: it omits `relay_proof`, and §9.7.4.2 R11 counts it as one unattributed source. **A resolver MUST NOT read a `relay_proof` whose `nonce` differs from the one it sent**, which is why the nonce is a request field rather than a value the relay chooses. **The proof covers the response and not the frame**: its `value_digest` is taken over the blob bytes the response returned, so one proof covers a whole QUERY response at one routing id, whatever number of frames that response carries.

**Relay-side validation has one home, and it is `03-identity.md` §3.10.2.** That section states the checks a validating SCP-native relay runs on PUBLISH and the slot-exclusivity rules that govern a routing id once a frame establishes a slot there; §9.7.4.2 R9 states the slot key, what a slot holds, the write rule, the serving order, and the eviction rule. This section states the frame's bytes and restates neither.

Relay-side validation is an optional capability, and `03-identity.md` §3.10.2 states what that means for a relay that omits it.

**Why raw binary, not MessagePack/CBOR.** The frame uses a raw, fixed-layout binary encoding under the §9.5.1 length-prefix discipline. A self-describing codec admits multiple valid encodings of one logical value (map-key ordering, integer width, string-vs-binary tags), which would break byte-identical cross-binding decoding and perturb the exact bytes handed to signature verification. The frame therefore fixes exactly one canonical encoding.

**Frame layout:**

```
KEY-EVENT-RECORD (KeyEventRecordV2) :=
  version:          u8         = 2           # frame version
  identifier:       [u8; 32]                 # the identity's inception-derived identifier (§9.7.4.2 R13)
  value:            [u8]                     # trailing remainder = one contiguous segment of the identity's key-event log (§9.6.1, §9.7.4.2 R9)
```

- **version** — a `u8`, currently 2. Any change to field encoding bumps the version. **This frame starts at 2 because `0x01` is a live wire version for a different grammar**: the superseded BEP44 DID-record frame the `scp-protocol` crate still implements and the key-event record replaces. This is not migration compatibility, which this pre-release protocol does not carry — the superseded frame is deleted when the key-event record lands in the crates, and `0x01` is then retired rather than reused.
- **identifier** — the identity's 32-byte inception-derived identifier. The relay's step 2 compares the registered routing derivation over this field against the `routing_id` the frame is published at. The identifier encodes no key (§9.7.4.2 R13), so nothing about the frame's authorization follows from it alone.
- **The frame carries no signature.** A signature over the frame would be checked against a key read out of the writer's own chain, and no frame that passes chain verification could fail it except by a byte change that chain verification already rejects, so the frame carries none and the relay's write decision is chain verification plus the slot rule (`03-identity.md` §3.10.2, §9.7.4.2 R9). **The frame carries no sequence number** either. An event's sequence is its position on the chain (§9.7.4.2 definitions), so a chain that extends a stored chain has a strictly higher head sequence by construction and the relay's write rule reads the extension rather than a number beside it; a frame-level sequence would restate the chain's own order in a field a writer supplies.
- **value** — the sole variable-length field, carried as the **trailing remainder** of the frame (no `value_len` prefix). Because every preceding field is fixed-width, `value` is unambiguously `frame_bytes[33..]`; a length prefix would be redundant with the blob's own length and a determinism footgun (two disagreeing lengths). `value` MUST be non-empty and its length MUST NOT exceed `Max blob size` (262144, §9.18.11) `− 33`. It carries one contiguous chain segment, and a relay serves a slot's chain as the ordered sequence of frames covering inception through head (§9.7.4.2 R9).

**`value` layout:**

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `first_sequence` | 8-byte big-endian u64 — the sequence of the segment's first event |
| 2 | `last_sequence` | 8-byte big-endian u64 — the sequence of the segment's last event |
| 3 | `event_count` | 4-byte big-endian u32 |
| 4 | `events` | `event_count` records in ascending sequence order, each a 4-byte big-endian length prefix over the event's §9.5.1 signed preimage bytes, followed by the signature field the event's kind, index lists and signature-form lists fix (§9.7.4.2 R3) |

A decoder MUST reject a frame whose `event_count` is zero, whose `last_sequence` is below its `first_sequence`, or whose declared range does not equal the sequences its events carry — `last_sequence − first_sequence + 1` events, each one sequence above its predecessor. The decoder reads the event's kind, its signer index lists, and its per-slot signature-form lists out of the preimage it just read, and derives the signature field's length from those three together with the two length prefixes each assertion-form slot carries inside itself (§9.7.4.2 R3, the closed signature layout). It walks the field slot by slot: a `0x01` slot is 64 bytes, and a `0x02` slot is a 4-byte length and that many bytes of `authenticatorData`, then a 4-byte length and that many bytes of `clientDataJSON`, then 64 bytes. A decoder MUST reject a slot whose `authenticatorData` length is below `MIN_AUTHENTICATOR_DATA_BYTES` or exceeds `MAX_AUTHENTICATOR_DATA_BYTES`, whose `clientDataJSON` length is zero or exceeds `MAX_CLIENT_DATA_JSON_BYTES` (§9.18.17), or whose declared length runs past the field, and MUST reject an event whose signature field does not end exactly where the last slot ends. **No length outside a slot states the field's size**, so the frame carries no second length for a decoder to disagree with. **The three lengths `value` itself supplies are bounded here too**, because `value`'s own trailing-remainder shape bounds none of them: a decoder MUST reject an event whose 4-byte preimage length prefix runs past the remaining `value` bytes; MUST reject a frame whose events do not end exactly at the end of `value`, so a relay cannot append bytes after the last event and have one binding accept the frame while another rejects it; and MUST NOT size any allocation from `event_count` before it has read that many events.

The fixed prefix is `1 + 32 = 33` bytes, and the total frame length is `33 + len(value)`. **The frame carries no public key and no root-set digest** either, for the reason the bullet above gives: a value the writer supplies would authorize the writer against itself.

**Every byte of the framing is unsigned, and the chain inside it carries the whole authority.** The frame's `version`, its `identifier` field, and its field boundaries are transport framing that no key signs. **A decoder MUST NOT derive any security-relevant conclusion from an unsigned field, and a relay MUST cross-check the one unsigned field a decision reads — `identifier` — against the verified chain before any decision reads it** (`03-identity.md` §3.10.2 step 3). Every other input a decision reads, the standing root set included, comes from the verified chain and never from the framing.

**Decoder determinism (normative).** Because the frame is decoded by hand-rolled, byte-identical decoders across every binding, a conformant decoder MUST enforce the following. Any frame that fails any rule is discarded exactly as a chain that fails verification is (§3.10.4) — never trusted, never partially parsed:

1. **Read and check `version` before any subsequent byte.** The `version` field gates the *entire* grammar. A decoder MUST read and validate `version` before interpreting any subsequent byte, and MUST reject (discard, no partial parse) any `version` it does not implement.
2. **Require the fixed prefix in full.** A decoder MUST reject any frame shorter than the 33-byte fixed prefix (`version + identifier`) — truncation is never a partially-valid frame.
3. **Bound-check the `value` length only after the prefix check.** `value` is the trailing remainder, `len(value) = total_frame_len − 33`. A decoder MUST NOT compute `total_frame_len − 33` before rule 2 has confirmed `total_frame_len >= 33`: computing it first can underflow, which diverges between a debug-build panic and a release-build wrap across bindings. With rule 2 satisfied the subtraction cannot underflow. A decoder MUST reject an empty `value` (`total_frame_len == 33`) and MUST reject `len(value) > Max blob size (262144, §9.18.11) − 33`. No widening is required: `len(value)` is an actual buffer length (a valid `usize`, already bounded by the transport's Max blob size) and the bound is a compile-time constant, so the frame itself carries no wire-supplied length field to overflow. **`value`'s own contents are a length-prefixed layout and carry three**, and the `value`-layout paragraph above bounds each one.
4. **Decode-and-verify at exactly one site.** Decoding a frame and verifying the chain its `value` carries happen at exactly **one** site (mirroring SCPM's single decode-and-verify site, §9.16.1). No other layer may test, branch on, or depend on the framing bytes.

**Publish / query contract.**

- **Publish** = wrap `(identifier, value)` in a key-event record frame and PUBLISH the frame bytes at the identity's routing ID (§3.10.5), one frame per contiguous segment and the segments in order. The relay blob MUST be the frame — not the bare key-event log bytes, and not an `OuterEnvelope`.
- **Query** = the existing QUERY operation (§3.10.4) with `limit: N` (N = 16) returns blobs stored at the routing ID; the resolver decodes each at the **single** decode-and-verify site, verifies the chain each `value` carries under §9.7.4.2 R2 and R3, and settles two chains that diverge by the fork-precedence rule (§9.7.4.2 R6). It reads no key from the frame. **A slot is an ordered sequence of frames, so one QUERY does not necessarily return a whole chain**, and the resolver pages the slot by the walk §9.7.4.2 R9 states, re-issuing QUERY with `since` set to the `stored_at` of the last frame it accepted. `N` bounds one page and bounds no slot; a chain at the `MAX_KEYS_PER_CHAIN` ceiling spans far more frames than `N` (§9.18.17 states the arithmetic). Against non-validating or foreign storage `limit: N` also lets the resolver retrieve up to N candidates and sift them by R2, R3, and R6 (§3.10.4 step 5). See §3.10.2 for why `limit: N` dominates `limit: 1`.
- **Distinct from the outer envelope.** An identity's routing ID carries key-event record frames, not `OuterEnvelope`s; a resolver MUST NOT deserialize one as the other. The two are disjoint at two independent levels: **(a) routing-ID space** — key-event records occupy `SHA-256("scp:did:" || identifier_bytes)` (§9.7.4.2 R13), disjoint from context routing IDs; **(b) byte level** — a frame begins with `version = 0x02`, and an `OuterEnvelope` is MessagePack-serialized as a map whose first byte is always a map marker (fixmap `0x80`–`0x8f`, or `0xde`/`0xdf`), never a low byte a frame version will take. The byte-level disjointness is a defense-in-depth backstop beneath the routing-ID separation.

**Two further frames carry the witness layer's objects, each at its own routing derivation.** §9.7.4.3 states both objects' fields and both signature preimages; this section states the frames' bytes and restates neither object.

```
COSIGNED-HEAD-RECORD (CosignedHeadRecordV3) :=
  version:    u8         = 3
  subject:    [u8; 32]                 # the cosigned identity's identifier (§9.7.4.2 R13)
  value:      [u8]                     # trailing remainder = one or more 240-byte cosigned heads (§9.7.4.3)

WITNESS-CONFLICT-RECORD (WitnessConflictRecordV4) :=
  version:    u8         = 4
  subject:    [u8; 32]                 # the subject identifier
  value:      [u8]                     # trailing remainder = one or more 248-byte conflict statements (§9.7.4.3)

SERVICE-RECORD-FRAME (ServiceRecordFrameV5) :=
  version:    u8         = 5
  identifier: [u8; 32]                 # the identity's identifier (§9.7.4.2 R13)
  value:      [u8]                     # trailing remainder = one service record and its 64-byte signature (`03-identity.md` §3.10.13)
```

A cosigned-head record is published at `SHA-256("scp:wit:" || subject_identifier_bytes)`, a conflict-statement record at `SHA-256("scp:wcf:" || subject_identifier_bytes)`, and a service-record frame at `SHA-256("scp:svc:" || identifier_bytes)` (§9.7.4.2 R13), so the address is the type discriminant for each exactly as it is for the key-event record above. **The service-record frame's `value` is the record's §9.5.1 signature preimage bytes after the separator, followed by the 64-byte signature** that `03-identity.md` §3.10.13's designated key produced over them, and a decoder MUST reject a frame whose `value` does not end exactly where that signature ends. `03-identity.md` §3.10.13 states the record's fields and its per-entry encoding, and this frame restates neither. **The witness layer's two objects are fixed-width, so each of those two `value` fields is a whole number of objects and the decoder needs no per-object length.** For those two a decoder MUST reject a frame whose `value` length is not a positive multiple of the object width its `version` names, and for all three it MUST read and validate `version` before any subsequent byte, MUST reject a frame shorter than the 33-byte fixed prefix, and MUST reject a `value` longer than `Max blob size` (262144, §9.18.11) `− 33`; the four decoder rules above govern these two frames unchanged. A cosigned-head record's objects are served in ascending `sequence` order. **The version bytes are distinct from the key-event record's `0x02`** so that a frame misdelivered across routing derivations fails on its first byte rather than on a field boundary, which is the same byte-level backstop the outer-envelope disjointness paragraph below states. Neither frame carries a signature of its own: each object inside `value` carries one, and the relay's write decision is verification of those signatures against the witness operator's key-event log plus the address binding of step 2.

**Divergence is defined over events, never over framing.** Where `03-identity.md` §3.10.4 compares two records serving heads of one chain, it compares **the chain bytes** the two `value` fields carry and the sequence the verified `value` states, never a field of the frame.

**TTL.** Key-event records reuse the shared relay `blob_ttl` (§9.10.2), bounded by `Max blob TTL` = 604800s / 7d (§9.18.11); there is no record-specific TTL. TTL governs storage lifetime, the chain's own order governs supersession (§3.10.7), and republication on the 6-day cycle is what makes a record permanent (§3.10.2).

## 9.11 Key Continuity Verification

**The fingerprint.** The key-continuity fingerprint is

```
SHA256("SCP-KEY-CONTINUITY-V1:" ‖ id_a ‖ count(a_root_set) ‖ a_root_set_members ‖ a_active_key
                              ‖ id_b ‖ count(b_root_set) ‖ b_root_set_members ‖ b_active_key)
```

taking the parties' 32-byte identifiers ordered by unsigned byte comparison, and each root-set member as a raw 33-byte SEC1 compressed point in the key state's own list order, under the repeated-field count rule of §9.5.1. One form covers a root set of any size. A second count-free encoding for the one-member case would make two SDKs compute two values for one pair and raise a maximum-severity alert on an honest pair.

Every key state a verifier accepts names exactly one `#active` key, because §9.7.4.2 R3 rejects a snapshot whose service-key designation names a key the snapshot does not list `current`, and rejects a snapshot listing more than one key `current` in any operational role. No sentinel stands in for an absent operational key.

**Why continuity carries the weight a rename used to carry.** An identifier does not change when its root changes, so no rename tells a relying party that the person behind an identifier may have changed, and fork precedence adopts a chain rather than authenticating a person. KERI states the property in `spec-body` §Autonomic identifier (AID): "Authoritative control over the identifier persists in spite of the evolution of the Key state." Re-verification against the current root set is the gate the rename used to supply.

**The standing.** The SDK keeps, for every identifier it has encountered, one `ContinuityStanding` with three values: `Verified`; `PendingReverify`, meaning the SDK observed a key change; and `Unresolved`, meaning the resolution delivered no chain. Beside the standing the SDK records the root-install digest as a field of the record and never as part of its key, because keying the record to a pair that includes the digest would make every root change look like a first encounter, which is the takeover this rule exists to catch. §9.6.4 assigns the standing on first contact.

`Unresolved` means the SDK learned nothing about the identifier and never that the identifier is suspect. One cause sets it: a resolution that delivered no chain. It clears on any later resolution that adopts a chain, with no human step.

**The two triggers.** A `RootRecovery` the SDK observes after the first encounter is a key change, whether the verifier adopted it or the identity is contested, and it is never a legitimate-change exemption. The observable trigger is the recorded root-install digest no longer matching the resolved chain's. On observing it the SDK MUST set `PendingReverify`, update the recorded digest, invalidate every recorded continuity verification for that identifier, and alert at maximum severity. An uncontested `RootRecovery` is exactly the attacker's outcome when a party took the pre-rotation key exclusively, so a verdict of `Adopted` exempts nothing.

A `KeyState` the controller did not author, on the local identity's own chain, is the device-compromise signal, and the device that holds that identity reads it alone: that SDK records the event and alerts the human at maximum severity, and a peer sets nothing on it. From a peer's position every `KeyState` of every other identity is unauthored, so a peer-side rule would set `PendingReverify` at every peer on every routine custody migration. KERI's `spec-body` §Indirect exchange via witnesses and watchers states the same division, where a controller watches its own witnesses.

A resolved contest clears the standing in one case and no other. Where §9.7.4.2 R6 ranks one suffix above the other and the verifier retires the rank-3 equivocation record, the standing stays `PendingReverify` where the winning suffix carries a `RootRecovery` the verifier had not already trusted on first use, and the verifier records the winner's root-install digest. Where the winning suffix carries no `RootRecovery`, the verifier restores the standing the identifier held before the contest. An escalation to a terminal tie clears nothing.

**The gate reads other identifiers.** The admission and grant gate below reads the standing of identifiers other than the local identity. A device that observes an unauthored change on its own identity's chain records it and alerts, and sets no standing against its own identifier. The gate would otherwise lock the controller's own second device out of every context after a custody migration, and the one stated exit is a fingerprint comparison one person cannot perform against themselves.

**The authoritative gate list.** While an identifier's standing is `PendingReverify` or `Unresolved`, the SDK MUST NOT: add a new leaf for it to a context; issue a UCAN to it; distribute a sender key to a new leaf of it; grant anything to a leaf it replaced; auto-accept it at the standing-pair consent gate, the known-identity allowlist, or a cached `author_keys` entry; or auto-accept an invitation, a standing-pair request, or a contact-graph promotion from it. `PendingReverify` withholds two further acts: accepting a UCAN that identifier issued, and accepting a UCAN carrying that identifier anywhere on its delegation chain. Alec approved the scope of the first three auto-accept gates on 2026-09-03. The two UCAN acts follow from a recovering controller being unable to enumerate the tokens an attacker issued, which makes refusal on the relying party's side the one act that stops them. This list is authoritative and every other section cites it.

`Unresolved` reaches neither UCAN act, because the verifier learned nothing about the identifier, and withholding those two acts would reach every token the victim ever issued on the strength of one relay's outage.

Every auto-accept gate reads a freshly resolved standing. Before auto-accepting, the SDK MUST resolve that identifier's key-event log within the attestation-resolution staleness bound of §9.18.7, and a log older than that bound fails closed to the manual path. The privacy cache never satisfies this check, because that cache runs to seven days for an inactive contact, so a gate reading a stored standing against a week-old resolution would auto-accept a taken-over identity for a week.

Every MLS handshake message from an identifier that is already a member is processed whatever its standing. RFC 9420 makes almost every Commit carry an update path, so one member holding a Commit while another member applies it forks the group's epoch. Standing acts one layer up: the verifier records the replaced leaf's attestation as unverified, grants that member nothing, and surfaces the change to the human.

The standing returns to `Verified` when the user completes re-verification against the identity's current root set by comparing the fingerprint out of band. While the identity is `Contested` the standing holds at `PendingReverify` and no user act clears it, because a contested identity has no single current root set to verify against.

**Where the remaining gates are written.** Five gates carry their standing check in the section that owns them: the broadcast per-author key cache in `05-contexts.md` §5.14.2, the standing-pair consent gate in `05-contexts.md` §5.15.8, the known-identity allowlist in `05-contexts.md` §5.12.2, the key response of §9.16.2 step 3, and the first-contact bootstrapping of §9.6.4. The Add gate, the UCAN gate, and the sender-key-to-a-new-leaf gate are written in the list above and in no other section.

## 9.12 Compromise Recovery Protocol

When a key is known or suspected to be compromised, the following ordered steps constitute the recovery protocol:

**1. Key rotation on trusted device.**
- **A delegated agent identity's key compromise:** an agent runtime is typically less secure than a device HSM, so a delegated agent identity's `#active` is the most likely key in a human-plus-agent pair to be compromised. **No delegated identity resolves today**, because §9.7.4.2 R3 rejects every chain whose `delegator` field is nonzero until the delegation model is specified, which it is not as of 2026-09-10 (`00-open-questions.md`); this bullet states the recovery that model will run and states no frequency about today. That identity runs the recovery protocol of this section on its own key-event log, because it holds its own root and its own operational key (§9.1 invariant 1). The human's `#active`, root UCANs, and root set are untouched, and the human revokes the scoped UCANs it issued to that agent identity (step 3). This is the cheapest recovery scenario for the human: no key of the human's changes.
- **Active Signing Key compromise (common case):** Generate a new active signing keypair; the standing root signs a `KeyState` (§9.7.4.2 R3) that lists the new `#active` `current` and the compromised key `Compromised{from: N}`, N = that `KeyState`'s sequence. **The position is what the log-anchored evidence class of §9.7.1 reads**; the content class bounds a key that is not `current` identically under all three non-`current` conditions, so recording that sequence is what stops the attacker from anchoring a destruction attestation or a durable snapshot behind the compromise, and not what bounds content. Every member of every context the identity belongs to runs step 1a on adopting that `KeyState`, which is what removes a leaf the attacker added under the stolen key. **The controller MUST then re-sign and republish its service record under the new `#active` before it destroys the old key** (`03-identity.md` §3.10.13, §3.2.1 case 1 step 3a-bis). `#active` is the key the designation resolves to, so every service record signed by the superseded key stops verifying the moment a reader adopts the `KeyState`, and a controller that skipped this step would leave the identity unroutable at every reader that adopted it. The identifier does not change. No root change is needed.
- **Root compromise (rare, severe), with or without operational-key compromise:** The controller signs a `RootRecovery` (§9.7.4.2 R3) with the pre-rotation key from independent custody — `standing_root: CoSigns` while it still holds a threshold of its root, `Lost` otherwise (§9.7.4.2 R10). The event installs a fresh root K′ generated under R10's device boundary and carries the complete post-recovery key state (§9.7.4.2 R8): every operational key by role — a fresh key for any key the compromised device also held, with the replaced key listed `Compromised{from: N}`, and the controller's own key re-listed otherwise; every other historical key re-listed in the condition it already carried, `Superseded` or `Retired`; the witness set; and the service-key designation, each diffed against the pre-compromise record per R10. The recovery carries no relay list: the controller re-points its relays by writing a service record under the newly designated key (§9.6.3, `03-identity.md` §3.10.13). The recovery supersedes any chain the attacker's root signed, wherever the attacker forked (§9.7.4.2 R6). The identifier does not change: no new identity is created and no forwarding record exists. Steps 1a–6 then run under the operational keys the snapshot names. **What the snapshot replaces is key state and nothing else.** It does not remove an MLS leaf the attacker added under the stolen `#active` in any context (step 1a covers it); it does not withdraw a KeyPackage the attacker published (the controller cannot enumerate them; they expire, and step 4 replaces the controller's own); it does not revoke a UCAN the attacker issued (step 3 covers the controller's tokens; §9.11's gate refuses a token issued **by** the flagged identifier, and one carrying it anywhere on the delegation chain, as each relying party encounters it, so no protocol enumeration of the attacker's tokens is needed); it does not undo auto-accept or contact-graph standing the attacker earned on peers, and §9.11's key-change rule is what withdraws it — the standing gates inbound auto-acceptance as well as outbound grants, so a peer that had auto-accepted the attacker stops doing so the moment it observes the recovery; it does not reach private-state events written under a stolen PSK (§3.7's re-key); and it does not withdraw an attestation the attacker issued (attestation verification is current-key-only, so the replaced key's attestations fail from the recovery on).
- **Pre-rotation key copied, root intact and trusted:** The controller signs a `CommitmentRollover` (§9.7.4.2 R3) immediately. The attacker can reveal the same commitment. **The controller wins the comparison outright and the identity is not contested** (§9.7.4.2 R6, the root rule, and §9.7.4.2's second worked example, which traces it event by event). The rollover also fixes a commitment the attacker cannot reveal, which forecloses a second attempt on the controller's suffix. No operational key changes, so for a rollover that fixes a commitment steps 1a–6 do not run; an abandoning rollover runs step 2 before it is published (§9.7.4.2 R4).
- **Retiring the identity (abandonment):** The controller, holding its root, issues the step-2 MLS Update in every context it belongs to, then publishes a `CommitmentRollover` declaring abandonment (§9.7.4.2 R4); each Commit is the abandonment boundary in its context (§9.7.1). Steps 3–6 do not run; relying parties that confirm the abandonment treat the identity's UCANs as revoked, its attestations as expired, and its sender keys as retired. If the controller suspects a copy of a pre-rotation key, it signs a `RootRecovery{CoSigns}` on its own suffix first and abandons under K′ (the failure-mode table). **What that order achieves and what it does not:** it consumes the standing commitment C first and installs K′, which forecloses the copy holder's extension past the commitment C′ that K′ fixes, so the copy cannot follow the identity forward. It does not end a contest, because the copy holder can still fork behind the `RootRecovery{CoSigns}`, reveal C there, and stand at rank 1 beside it (§9.7.4.2 R6). No order of key material retires an identity whose pre-rotation key was copied; the failure-mode table's copied-P row states the outcome and this bullet adds nothing to it.
- **Pre-rotation key copied, root lost:** The controller signs a `RootRecovery{Lost}`; the attacker can too. Neither event carries the standing root's signature, because neither party holds that root, so both suffixes are rank 2 and the identity is `Contested`, terminal by key material (§9.7.4.2 R7). Step 1a proposes Remove for no leaf while the contest stands, because R7 gives no party a `current` key state to test leaves against, and steps 2–6 do not run while it stands.
- **Pre-rotation key exclusively the attacker's, whatever the state of the root:** The attacker's `RootRecovery{Lost}` is rank 2 and the controller's chain reveals nothing, so the controller is rank 3 and the attacker wins uncontested (§9.7.4.2 R6; §9.7.4.1's failure-mode table). The root cannot be recovered by key material.
- **Root compromised with the pre-rotation key copied:** both parties hold a threshold of the root and enough of the next set, so both produce a `RootRecovery{CoSigns}` at rank 1 and the identity is contested, terminal by key material (§9.7.4.2 R7; §9.7.4.1's failure-mode table states the same row and this bullet restates none of it). In every row where the root cannot be recovered by key material, the person establishes a new identity, and each context's admins — after confirming the head from a relay in the fallback set, which the hostile identity's service record does not name (§9.7.4.2 R4, definitions) — remove the old identity and admit the new one; §3.3's social recovery does not apply, because it re-establishes custody of the same identity.
- **The controller's own identity is contested:** the SDK keeps extending the controller's suffix (§9.7.4.2 R10) and tells the human the tie class R7's verdict carries; it does not sign a further reveal, because both suffixes have already consumed the standing commitment.
- **Leaf-key / MLS-state compromise (ephemeral leaf key leaked, identity keys intact):** An attacker who extracts a member's MLS leaf state holds the leaf `signature_key`/`encryption_key` and the standalone **KeyPackage attestation** over them (§9.7.1). Beyond in-group PCS (§9.7.3), the standalone attestation lets the attacker reuse the leaf to join **other** groups until it expires. **An extracted leaf state also yields the leaf's `scp_wrapping_key` (`0xFF01`) private half**, and that key is stable across epochs (§9.16.1) and now decrypts three things rather than one: every §9.16 sender-key distribution addressed to this member, every invitation bundle addressed to this identity (`05-contexts.md` §5.12.3.1), and, where this identity is a context admin, that context's `participation_signing_seed` (`07-trust-validation-and-capabilities.md` §7.3.2.1). The containment sentence below was written when the wrapping key decrypted sender keys alone, so remediation now includes step 4's wrapping-key rotation and re-wrap and is not `#active` rotation on its own. Remediation is otherwise an **existing operation, not a new mechanism**: the victim rotates `#active` by a `KeyState` signed by the standing root — the same rotation used for active-key compromise above — and every member of every affected context runs step 1a on adopting it, which is what evicts a leaf the attacker already placed in a group. This **invalidates every outstanding KeyPackage attestation within `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (§9.18.7 — 5 min, the hard current-key freshness bound of §9.7.1 check 2)** — near-immediate, not instantaneous — because every one of them was signed by the now-retired verification method and verifiers resolve the identity's `current` `#active` only (§9.7.1 check 1), from a key state no more than 5 minutes stale (§9.7.1 check 2); once the retired key no longer resolves (and no fresh-enough pre-rotation cache entry remains), every attestation signed by it fails verification at every Add, everywhere, within that bound. **An already-admitted member's Updates follow the Update posture instead** (§9.7.1, Resolution failure policy): a party that can sustain a resolution outage against the members of one context keeps that context on its last-known-good key state, and the honest upper bound there is `MAX_KEYPACKAGE_ATTESTATION_LIFETIME` (§9.18.7 — 84 days), not five minutes. The victim then re-issues fresh KeyPackages/attestations under the new key (step 4) and issues MLS Updates in active contexts (step 2). **Containment property:** a leaked *leaf* key does NOT expose `#active` — separating the ephemeral, context-scoped leaf key from the identity signing keys is the entire point of the attestation model (§9.7.4), so this recovery is a **routine key rotation, not an identity-key exposure**: no recovery event (§9.7.4.2), no pre-rotation-key consumption, no change of identifier. This is a **Tier-1 revocation** of the attestation: the key state already lists the `current` key, and rotating it is the sole, sufficient act that stops the leaf from joining further groups — **no `attestations_valid_after` watermark or other new key-state field is introduced** (a document-level revocation watermark was considered and rejected as over-engineering; rotation of an already-present key is a complete and cheaper revocation).

**1a. Leaf re-verification after a key-state change.** Every member of a context who **adopts** any state-carrying event for a fellow member — a `KeyState` or a `RootRecovery` — after which a leaf's attesting key is no longer `current` MUST re-verify every leaf in that group carrying that identity against the adopted key state. **The Remove test is the signature test, and it carries a grace:** the member proposes Remove for a leaf when the leaf's KeyPackage attestation does not verify against the key the adopted state lists `current` for the `signing_key_id` that leaf names (§9.7.1 check 3) **and** the identity has committed no replacement leaf in that group within `LEAF_REPLACEMENT_GRACE` (§9.18.17) of the member adopting the state-carrying event. Comparing the `signing_key_id` fragment instead would evict nothing, because every leaf names `#active`, and the snapshot lists a fresh key under that same fragment.

**The grace exists because the signature test alone cannot tell two leaves apart.** After an identity rotates `#active`, two leaves in a context fail the test identically: an attacker's leaf, attested under the stolen retired key, and the identity's **own live leaf**, attested under the retired key because its replacement is step 2's Update, which has not committed yet. A peer that adopted the `KeyState` on its own resolution cycle before that Update landed would propose Remove for both, and a planned custody migration (`03-identity.md` §3.2.1 case 1) would evict the migrating member from its own context. The grace gives the identity one leaf-replacement interval to commit the Update, and the recovering controller's own enumeration below closes the grace early for the leaves it names, because the controller holds evidence a peer does not. A PCS Update heals a leaked leaf secret and does not evict a member, so this step is the only thing that removes a leaf the attacker added — and the most common compromise, `#active`, is remediated by a `KeyState`, so a step that fired only on a `RootRecovery` would leave the attacker's leaf in place for exactly that case.

**On a `Contested` verdict this step proposes Remove for no leaf.** R7 forbids a contested identity a `current` key state, so no member holds the basis the signature test reads, and three members applying the step to a contested identity would evict three different sets of leaves. A member holds the contested verdict, withholds the acts §9.11 names, and waits for the contest to resolve.

The recovering controller's own SDK MUST enumerate every leaf under its identity in every context it can reach and propose Remove for each one whose attestation it did not sign, and it proposes those Removes without waiting out `LEAF_REPLACEMENT_GRACE`, because "an attestation I did not sign" is a discriminator only the controller holds. Where the attacker is the sole admin of a context, no member can issue the Remove and the context is re-created (§5.9); that outcome is stated, not hidden.

**1b. Witness submission.** After the controller has published a key event and durably retained it, it submits that event to the witness set its snapshot names and re-submits until it holds a cosigned head over the new head (§9.7.4.2 R10, §9.7.4.3). **Submission gates nothing:** the event takes effect at every relying party the moment that party adopts the chain, because no rule of §9.7.4.2 reads a cosignature. A controller that submits to no witness loses portable freshness evidence and loses nothing else. **Where the designated witnesses are unreachable, silent, or refusing**, the controller replaces them with a `KeyState` naming a fresh set (§9.7.4.2 R10), which spends no commitment.

**2. MLS Update in all active contexts.** Issue MLS Update proposals in every context. This Commit is the identity's compromise boundary in that context (§9.7.1), and every member records that epoch as the retired key's boundary value so a later context snapshot or export carries it to members who did not observe the Commit (§9.7.1). This provides post-compromise security: new epoch keys are derived from the new key material, making the compromised old key useless for future messages. If the old key is unavailable (device stolen), a trusted co-member with admin role must remove and re-add the member. **In a context where no Commit ever records the retirement** — the controller cannot reach it, or the step-ordering paragraph below flags it for manual re-join — that context's log records no retirement Commit for the key, so §9.7.1 makes the absence a fact about the context rather than a gap: its members read their Commit history, find none, and keep verifying that key's content there. A rule that rejected instead would discard every message and every governance vote that identity ever signed in that context, which is the outcome §9.7.1's content class exists to prevent.

**3. UCAN revocation.** Revoke all UCAN tokens issued by the compromised key. Add revocations to each context's `RevocationList` and distribute via MLS application messages (§9.5). Issue new tokens signed by the new key.

**4. KeyPackage attestation rotation, and the wrapping-key re-wrap.** Delete all outstanding KeyPackages carrying an attestation signed by the old `#active` key from relays. Publish fresh KeyPackages whose leaves carry **KeyPackage attestations re-issued under the new key** (§9.7.1). **Rotate the `scp_wrapping_key` (`0xFF01`) in the same step**, because §9.16.1 makes an identity-key rotation one of its two triggers, and **before the old private half is destroyed, re-wrap every payload addressed to it**: the member's current sender key to every non-blocked member (§9.16.2), and — where this identity is a context admin — that context's `participation_signing_seed` to the new wrapping key, in the same governance event that publishes it (`07-trust-validation-and-capabilities.md` §7.3.2.1). A controller that destroyed the old private half first would strand the seed, which §7.3.2.1 says invalidates every participation statement that context ever issued. The KeyPackage leaves themselves remain self-signed by their ephemeral MLS leaf signature keys — it is the attestation, not the KeyPackage/leaf, that the rotated DID key re-signs.

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

**Self-hosted relay exception:** **a relay URL may use `ws://` if and only if the resolver took it from a service record whose signature it verified against the designated service key of a key-event log it verified under §9.7.4.2 R2 and R3** — the log authenticates the designated key and that key authenticates the relay list, so the two verifications together make the URL self-certifying, whichever relay served either object (§9.6.1, §9.6.3, `03-identity.md` §3.10.13). The SDK MUST reject a `ws://` relay URL from every other source, `.well-known/scp` and an unverified service record among them, because such a source carries no signature binding the URL to the identity and a substituted URL would downgrade the transport unnoticed. This section is the one home of that criterion. Such relays have no domain and cannot obtain CA-signed certificates; MLS provides the confidentiality boundary, and TLS on a dumb pipe protects already-encrypted traffic.

## 9.14 Clock and Ordering Model

**Clock model:** SCP does not require synchronized clocks. Timestamps are best-effort, used for ordering hints and replay detection, not for security-critical decisions.

**Clock skew tolerance:** 5 minutes. Messages with timestamps more than 5 minutes in the future are rejected. This is generous enough to handle devices with poorly-set clocks while tight enough to limit replay windows. **Two further readers apply the tolerance, and one of them gates a verdict.** A witness compares the `observed_at` it is about to write against its own clock and against its stored value, which decides whether that witness cosigns and decides nothing else (§9.7.4.3). **A resolver compares the `observed_at` of a relay proof of control against its own clock, and that comparison decides an R11 verdict** (§9.7.4.2 definitions, R11): a resolver whose clock is out by more than this tolerance counts no proven source, meets no first-contact floor, and returns `Inconclusive{SingleSource}` with the clock-skew rejections counted separately. The direction is fail-closed. No key event's own acceptability reads a clock.

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
  platform_attestation:  PlatformAttestation?  // absent on a .softwareOnly record; a .hardwareBacked record rates as software-only without a verified one
  method:                .hardwareBacked | .softwareOnly
  signature:             P256Signature          // 64 raw bytes, signed by #active (Active Signing Key); NOT a root member (the root signs establishment events only, §9.7.4.2 definitions)
}
```

§9.5.2 fixes the field order and encoding of the signed preimage, and every field above except `signature` is inside it — `key_state_head` included, so the anchoring position is signed rather than supplied beside the signature. **A human identity's own `#active` signs a destruction attestation, and a delegated agent identity MUST NOT sign one**: an agent destroys no context's key material on the human's behalf, and a verifier rejects a destruction attestation signed under a delegated identity.

4. Attestations are published to relays, outside the now-destroyed context, so they remain readable after the context keys are destroyed. They are **log-anchored evidence** (§9.7.1): the `key_state_head` field carries the value §9.7.1's log-anchored row constructs, and a verifier accepts the signature iff the signing `#active` was `current` at that position. A later routine rotation of `#active` therefore leaves every earlier destruction attestation verifiable, which is the property the attestation class would not give it — a signer that could void its own past destruction claims by rotating a key it controls would be publishing no evidence at all. **Where the key state lists the signing key `Compromised{from: N}`, the anchor alone proves nothing**, because the signer chooses `key_state_head` and the holder of a compromised key chooses a position before N. §9.7.1 states the one condition under which a verifier accepts such an artifact — it held the artifact before it adopted the event carrying N — and states that the class gives no guarantee otherwise.

**Trust levels for destruction claims.** Each level rates the method a consumer verified, never the method the record declared:

- **Hardware-attested** (Secure Enclave / Keystore attestation, where a verification of that attestation returns a pass): High confidence. The hardware claims the key is gone.
- **Software-only** (`memset(0)` on key material in memory), and every record declaring `.hardwareBacked` that no verified `platform_attestation` accompanies: Moderate confidence. Memory dumps, swap files, or crash logs may have retained the key.
- **No attestation** (member went offline before close): No confidence. The member may still have the key.

**Ruling (2026-08-25): a hardware-backed declaration rates as software-only until a verified platform proof accompanies it.** Alec ruled that a hardware-backed declaration reads as software-backed unless a verified platform attestation proof accompanies it. §27.4.6 of the attestations spec quotes the three statements he wrote and names the binary an agent posed to him; the sentence before this one states what those statements decided and is not his wording. Answering that binary is also what keeps the High-versus-Moderate split above: the arm he rejected removed the rating and left `method` describing a setup. The three levels above carry his answer: a record's `method` field is the publisher's declaration and is not the input to the rating, and a consumer reaches High confidence only through a verification of the `platform_attestation` the same record carries. A record declaring `.softwareOnly` needs no proof and rates as Moderate. §27.4.6 of the attestations spec (`.docs/specs/27-attestations.md`) states the ruling in four clauses and gives the reasoning Alec used to reach it; this section states no reading rule beyond the level assignments above, so the two cannot drift apart on the rule's wording.

No SCP implementation verifies a destruction `platform_attestation` today, and no artifact states the checks such a verification would run — open questions OQ-2 and OQ-29 of the attestations spec own that procedure. The §9.5.2 preimage table above places `platform_attestation` inside the signed bytes, and the shipped signing payload leaves it outside, so a holder of a shipped record detaches the proof from the signature that binds `method`; contradiction C34 and open question OQ-8 of the attestations spec carry that divergence, and against a shipped record a verification of the proof establishes nothing about the declaration beside it. Every published `.hardwareBacked` record therefore rates as Moderate confidence today.

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

**Wrapping key terminology.** The sender-side key layer uses two distinct wrapping keys, both HPKE-based (RFC 9180 Base mode, §9.5) but serving different roles: (1) the **stable wrapping keypair** (below) protects the persistent per-sender AES-256 symmetric key during key distribution — it is long-lived and published in the MLS LeafNode; (2) the **ephemeral wrapping keypair** (§9.16.2) protects per-request key material during individual key exchanges — it is generated fresh for each `SenderKeyRequest` and discarded after use. Both use DHKEM(P-256) + HPKE for key encapsulation, but the stable key enables offline key distribution while the ephemeral key provides forward secrecy for individual key exchanges.

**Stable wrapping keypair.** Each member maintains a single dedicated DHKEM(P-256) keypair per context (one per identity, because a delegated agent identity joins a context as its own member and publishes its own wrapping key), used exclusively for HPKE wrapping of sender key distributions (§9.16.2). This keypair is published as an MLS LeafNode extension (`scp_wrapping_key`) and is distinct from the MLS leaf HPKE key used for MLS key agreement. The wrapping keypair does NOT rotate on MLS Updates (epoch advances) — it remains stable across epochs so that sender key distributions can always be unwrapped, even by members who are offline during epoch transitions or who join after an epoch advance. **The wrapping keypair rotates on exactly two triggers, and this sentence is the one home of that rule:** (1) an identity-key rotation (§9.12), or (2) suspected compromise of the wrapping key. On rotation, the member publishes the new wrapping public key in its LeafNode extension via an MLS Update and re-distributes its current sender key to every non-blocked member under the new wrapping keys. **Two further payloads now ride this key and each carries a re-wrap obligation on the same two triggers:** the invitation bundle's HPKE recipient key (`05-contexts.md` §5.12.3.1) and the `participation_signing_seed` a context's governance state wraps to its admin (`07-trust-validation-and-capabilities.md` §7.3.2.1). §9.12 step 4 states the ordered re-wrap, and §7.3.2.1 states the obligation over the trigger rather than over the actor.

### 9.16.2 Key Distribution (Pull-Based)

Sender keys are distributed via a pull-based request/response protocol. When a sender generates or rotates a key, they publish a lightweight epoch advance notification as an MLS application message. Members request the actual key material on demand via directed MLS application messages. This replaces a push-based model where the sender would HPKE-encrypt the key to every recipient in a single message — the pull model reduces block cost from O(N) to O(1) on the sender side and naturally load-balances key distribution.

**Protocol flow:**

1. **Epoch advance notification.** When a sender generates or rotates their key, they publish a `SenderKeyEpochAdvance { sender_did, epoch, signature }` as an MLS application message. The signature covers `context_id || sender_did || "key_epoch" || epoch`, signed by the sender's Active Signing Key (`#active`). This is **O(1)** regardless of group size.

2. **Key request.** Members who need the key (because they see a new epoch, or because they just joined) send a `SenderKeyRequest { requester_did, sender_did, epoch, wrapping_pubkey, signature }` as an MLS application message with `recipient_hint` directed to the key holder. The `wrapping_pubkey` is a fresh ephemeral DHKEM(P-256) key generated per request.

3. **Key response.** The key holder's SDK processes the request: verifies the signature, checks the block list, and reads the requester's `ContinuityStanding` (§9.11) — a sender key is never distributed to a **new leaf** of an identifier whose standing is `PendingReverify`, while a leaf that already holds the key keeps it, because withholding from an existing member would stop the context rather than the takeover. If the requester is not blocked, responds with `SenderKeyResponse { sender_did, epoch, hpke_sealed_key, ephemeral_pubkey, request_nonce }` via an MLS application message with `recipient_hint` to the requester. The sender key is sealed using HPKE Base mode (RFC 9180) to the requester's ephemeral wrapping public key. If blocked, no response — the blocked party cannot obtain the key. The `ephemeral_pubkey` field carries the HPKE encapsulated key (`enc` in RFC 9180 terminology) and `hpke_sealed_key` carries the AEAD ciphertext (`ct`).

**HPKE Base mode specification (RFC 9180).** Sender key distribution uses HPKE Base mode (`mode_base`, §5.1.1 [no such section] of RFC 9180) with the following suite:

- **KEM:** DHKEM(P-256, HKDF-SHA256) — KEM ID `0x0010` (RFC 9180 §7.1)
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
4. Alice sends a **signed** block notification to Bob as an MLS application message: `{"type": "block", "blocker": "<Alice's identifier>", "blocked": "<Bob's identifier>", "signing_key_id": "#active", "timestamp": unix_ms, "signature": "<P-256, 64 raw bytes>"}`. The signature covers the canonical hash `SHA-256("SCP-BLOCK-NOTIFICATION-V1:" || len(context_id) || context_id || len(blocker_did) || blocker_did || len(blocked_did) || blocked_did || len(signing_key_id) || signing_key_id || timestamp_BE)` — see the BlockNotification row in §9.5.2 for field order and encoding. `alice_signing_key` is Alice's Active Signing Key (`#active`); the `signing_key_id` field tells the verifier which verification method of Alice's key state to resolve. The signature prevents forgery — without it, any group member could impersonate Alice and trick Bob into rotating his sender key. MLS application messages prove group membership but not individual sender identity within the message payload.
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
- **Access Key:** AES-256, per member per context. Generated at join time. Used to wrap/unwrap CEKs. Stored in the member's local key store and distributed via HPKE Base mode (RFC 9180), using the same suite as sender key distribution (§9.16.2): DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. The HPKE `info` string for access key distribution MUST use a distinct domain separator: `info = "scp-access-key-v1" || BE32(len(context_id)) || context_id || BE32(len(member_did)) || member_did || epoch_bytes` (vs `"scp-sender-key-v1"` for sender keys). The `aad` is: `aad = BE32(len(context_id)) || context_id || BE32(len(member_did)) || member_did || epoch_bytes`. Where `epoch_bytes` is the 8-byte big-endian encoding of the access key epoch. This prevents cross-protocol key confusion — an HPKE ciphertext produced for sender key distribution cannot be substituted for an access key distribution response (different `info` produces different derived keys).
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
| Signature algorithm | ECDSA on NIST P-256 with SHA-256 (FIPS 186-5) | All identity keys, envelope signatures, UCAN (ES256), MLS leaf credentials. **The RFC 6979 and low-`s` rules scope to §9.5.1 constructions**: every signer of one emits low-`s`, a software signer of one draws its nonce under RFC 6979, and a verifier of one rejects high-`s`. RFC 9420 governs an MLS-layer signature and RFC 7518 governs a JOSE ES256 signature on an outside party's UCAN, and neither takes the low-`s` rule (§9.5) | §9.5 |
| MLS ciphersuite | `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` (RFC 9420 ciphersuite 2) | RFC 9420 §17.1 | §9.5 |
| HPKE suite (DID-to-DID) | DHKEM(P-256, HKDF-SHA256) (KEM ID `0x0010`), HKDF-SHA256, AES-128-GCM | RFC 9180 Base mode | §9.5 |
| Key distribution HPKE | DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM | Same suite for sender key, access key, broadcast key | §9.5 |
| Merkle tree hash | SHA-256 | RFC 6962 §2 construction | §9.5 |
| Merkle leaf prefix | `0x00` | `SHA-256(0x00 \|\| event_data)` | §9.5 |
| Merkle interior prefix | `0x01` | `SHA-256(0x01 \|\| left \|\| right)` | §9.5 |
| Empty tree root | `SHA-256("")` = `e3b0c442...7852b855` | Hash of empty string | §9.5 |
| CEK size | 32 bytes | AES-256 key for content encryption | §9.17 |
| CEK wrapped overhead | 8 bytes | AES-256-KW check value | §9.17.7 |
| HPKE nonce size | 12 bytes | Managed internally by RFC 9180 | §9.5 |
| SCP signature size | 64 bytes | Raw `r \|\| s`, never DER; low-`s` enforced | §9.5 |
| P-256 signature-verification key size | 33 bytes | SEC1 compressed point | §9.5 |
| HPKE public key size (DHKEM(P-256)) | 65 bytes | Uncompressed SEC1 point, RFC 9180 §7.1 `Npk` | §9.5 |
| MLS signature public key size | 65 bytes | Uncompressed SEC1 point, RFC 9420 §5.1.2 | §9.5 |

#### 9.18.2 Domain Separators

All domain separators are UTF-8 strings used as prefixes in canonical hash, signature-preimage, or key/id-derivation constructions (§9.5.1 governs signature preimages; other constructions — key/id-derivation domains and id-construction prefixes — are noted per row). Most entries are §9.5.1 field-enumerated signature-preimage separators; the table also includes non-§9.5.1 entries (for example the `"standing:"` / `"standing-"` context-id construction prefixes, §5.15.8), and §9.4.3 directs a future secret-bearing saga to register its `"scp/saga-commit/<saga-type>/v1"` commitment separator (a commitment-hash domain, also non-§9.5.1) here. Each separator identifies the struct or derivation being hashed to prevent cross-protocol hash confusion.

| Domain Separator | Used For | Spec Reference |
|------------------|----------|----------------|
| `"SCP-INNER-ENVELOPE-V1:"` | InnerEnvelope signing | §9.5.2 |
| `"SCP-BROADCAST-ENVELOPE-V1:"` | BroadcastEnvelope signing | §9.5.2 |
| `"SCP-EPOCH-ADVANCE-V1:"` | SenderKeyEpochAdvance signing | §9.5.2 |
| `"SCP-KEY-REQUEST-V1:"` | SenderKeyRequest signing | §9.5.2 |
| `"SCP-ATTESTATION-V1:"` | Attestation signing | §9.5.2 |
| `"SCP-CUSTODY-VIOLATION-V1:"` | `ScpCustodyViolationAttestation` signing — ADR-039 layer-4 custody-violation record, signed by its detecting verifier | §9.5.2 |
| `"SCP-COUNTER-ATTESTATION-V1:"` | `CounterAttestation` signing — a subject's counter-claim against a custody-violation record, signed by that subject's `#active` key | §9.5.2 |
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
| `"SCP-KEY-EVENT-V1:"` | WebAuthn challenge domain for a key-event assertion-form signature slot — the authenticator's challenge is `"SCP-KEY-EVENT-V1:" \|\| event_preimage_digest` and a verifier compares its unpadded base64url form against `clientDataJSON.challenge`; a challenge-construction prefix, NOT a §9.5.1 signature-preimage separator, and distinct from `"SCP-KEL-EVENT-V1:"` above so that no key-event preimage is ever a WebAuthn challenge and no WebAuthn challenge is ever a preimage | §9.7.4.2 definitions |
| `"SCP-CUSTODY-PROBE-V1:"` | Custody-reachability probe domain for §9.7.4.1 item 5d — the SDK takes one test signature over `SHA-256("SCP-CUSTODY-PROBE-V1:" \|\| 32 fresh random bytes)`, or over that same value as a WebAuthn challenge for the assertion form. It is registered so that no probe value can equal a key-event preimage or a key-event WebAuthn challenge, which is what stops a compromised assembling device using the probe to obtain a signature over an event it composed | §9.7.4.1 item 5d |
| `"SCP-KEL-ID-V1:"` | Inception-derived identifier — `SHA-256("SCP-KEL-ID-V1:" \|\| inception_signed_preimage)`, with the inception's identifier and predecessor-digest fields set to the all-zero placeholder; an identifier-construction prefix, NOT a §9.5.1 signature-preimage separator | §9.7.4.2 R13 |
| `"SCP-RELAY-PROOF-V1:"` | Relay proof of control — one community-relay-list operator's signed statement that the relay serving a QUERY is the one its entry names, over the requester's nonce, the routing id served, and the digest of the bytes served; §9.7.4.2's definitions state the field set and the five checks a resolver applies, and §9.7.4.2 R11 states the floor it feeds | §9.7.4.2 definitions, R11 |
| `"SCP-SERVICE-RECORD-V1:"` | Signature preimage of the service record — `SHA-256("SCP-SERVICE-RECORD-V1:" \|\| identifier \|\| sequence \|\| entries)`, signed by the operational key the key state designates for the service record | `03-identity.md` §3.10.13 |
| `"scp:did:"` | Key-event record routing derivation — `SHA-256("scp:did:" \|\| identifier_bytes)`; an id-derivation domain, NOT a §9.5.1 signature-preimage separator | §9.7.4.2 R13 |
| `"scp:svc:"` | Service-record routing derivation — `SHA-256("scp:svc:" \|\| identifier_bytes)`; an id-derivation domain, NOT a §9.5.1 signature-preimage separator | `03-identity.md` §3.10.13 |
| `"scp:wit:"` | Cosigned-head routing derivation — `SHA-256("scp:wit:" \|\| subject_identifier_bytes)`; an id-derivation domain, NOT a §9.5.1 signature-preimage separator | §9.7.4.2 R13, §9.7.4.3 |
| `"scp:wcf:"` | Conflict-statement routing derivation — `SHA-256("scp:wcf:" \|\| subject_identifier_bytes)`; an id-derivation domain, NOT a §9.5.1 signature-preimage separator | §9.7.4.2 R13, §9.7.4.3 |
| `"SCP-RESET-REQUEST-V1:"` | Sync reset request signing | §23.5.2 |
| `"SCP-KEY-CONTINUITY-V1:"` | Key continuity fingerprint hash | §9.11 |
| `"SCP-CHECKPOINT-V1:"` | Event log checkpoint hash — **content class** (§9.7.1): a member accepts a checkpoint through MLS inside the context, so the context epoch orders it | §11 |
| `"SCP-EVENT-V1:"` | Event log entry hash | §11 |
| `"SCP-EXPORT-ENTRY:"` | Context export chain hash | §5.13 |
| `"SCP-OUTLET-REGISTRATION-V2:"` | Outlet registration integrity hash | §6.2 |
| `"SCP-KEY-DESTRUCTION-V1:"` | Key destruction proof — a **log-anchored evidence** separator, one of the five §9.7.1's classification table lists, with `"SCP-CONTEXT-SNAPSHOT-V3:"`, `"SCP-CONTEXT-EXPORT-V3:"`, `"SCP-COSIGNED-HEAD-V1:"` and `"SCP-WITNESS-CONFLICT-V1:"`; the artifact carries the digest of the signer's key-state head at signing | §9.15 |
| `"SCP-COSIGNED-HEAD-V1:"` | Cosigned head — one witness's signed statement of the subject chain's head at one moment; a **log-anchored evidence** separator, keyed on the witness's own `witness_key_state_head` | §9.7.4.3 |
| `"SCP-WITNESS-CONFLICT-V1:"` | Witness conflict statement — one witness's signed statement that two chains for one subject were offered to it; a **log-anchored evidence** separator, keyed on the same field | §9.7.4.3 |
| `"scp-pseudonym-routing-v1:"` | Per-context pseudonym routing id — `SHA-256("scp-pseudonym-routing-v1:" \|\| context_pseudonym)` over the 33-byte compressed pseudonym public key, which is the 32-byte value every routing field carries; a routing-derivation prefix, NOT a §9.5.1 signature-preimage separator | §9.10.4 |
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
| `"SCP-CONTEXT-SNAPSHOT-V3:"` | Tier-2 sync-delta context snapshot signing; the `-V3:` preimage carries `key_state_head` and `key_boundaries_hash` | §23.16.4 |
| `"SCP-CONTEXT-EXPORT-V3:"` | Signed context export snapshot signing; the `-V3:` preimage carries `key_state_head` and the whole snapshot, `key_boundaries` included | §23.16.8 |
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
| Min active voters for fallback | 2 | Minimum voters for governance timeout fallback | §6.4 [no such section] |
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
| MLS extension type: `scp_wrapping_key` | `0xFF01` | RFC 9420 §17.3 private-use range; carries the DHKEM(P-256) sender-key wrapping public key | §9.16 |
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

| Constant | Value | Derivation | Read by |
|----------|-------|------------|---------|
| `MAX_ROOT_SET_SIZE` | 16 | An organization's officer set fits, and a cap of 64 would let one event carry 4 KB of signatures | §9.7.4.2 R3's defect list; the installed-root-set field of the key-event preimage |
| `MAX_NEXT_SET_SIZE` | 16 | Same derivation as the root-set cap | §9.7.4.2 R3's defect list; the reveal group; the next-threshold recommendation of §9.7.4.1 item 4 |
| `MAX_RETAINED_SUFFIXES` | 8 | Two of a controller's devices plus several attacker forks fit with margin | §9.7.4.2 R9's admission and eviction rules and its two-object bound; the slot cap of a validating relay; the conflict-statement cap of `03-identity.md` §3.10.2 |
| `MAX_WITNESS_SET_SIZE` | 32 | The witness set is a repeated field of the preimage the key entries sit in, so an unbounded set puts an event past one frame's `value` bound | §9.7.4.2 R3's defect list and R9's retained-object bound; the SDK's default witness set in §9.7.4.3 |
| `MIN_AUTHENTICATOR_DATA_BYTES` | 37 | Web Authentication Level 2, section 6.1, fixes an assertion's `authenticatorData` at a 32-byte `rpIdHash`, a flags byte, and a 4-byte counter, and the flags byte the user-presence check reads sits at byte 32 | The assertion-slot layout of §9.7.4.2 definitions; the frame decoder of §9.10.12 |
| `MAX_AUTHENTICATOR_DATA_BYTES` | 256 | WebAuthn adds only CBOR extension outputs past 37 bytes | The assertion-slot layout; the frame decoder of §9.10.12; §9.7.4.2 R3's copy-level-defect rule |
| `MAX_CLIENT_DATA_JSON_BYTES` | 512 | The members SCP reads run near 160 bytes once a browser adds `origin` and `crossOrigin` | The assertion-slot layout; the frame decoder of §9.10.12 |
| `KEY_ALGORITHM_ECDSA_P256_SHA256` | `0x01` | The one variant registered for v1, naming the ciphersuite §9.5 mandates | §9.7.4.2 R3's unrecognized-algorithm rejection; the key-state snapshot layout |
| `MIN_WITNESSING_INTERVAL` | 300 s (5 min) | A zero interval would make self-observation an unbounded fetch loop and put every witness into a continuous cosigning loop | §9.7.4.2 R3's defect list and R10; §9.7.4.3 |
| `MAX_WITNESSING_INTERVAL` | 604800 s (7 d) | The interval is the floor on the controller's self-observation cadence, and seven days is the point past which a controller would read its own chain less often than a relay's maximum blob TTL | §9.7.4.2 R3's defect list; R10's self-observation floor |
| `DEFAULT_WITNESSING_INTERVAL` | 3600 s (1 h) | Chosen against the self-observation cadence it fixes: hourly reaches the device-compromise signal of §9.11 within one working day and costs a quiet identity 24 fetches a day | The SDK's default witness set in §9.7.4.3; §9.7.4.2 R10 |
| `MAX_SUBJECTS_PER_WITNESS` | 10,000,000 | At about 112 bytes per record the store stays near a gigabyte, which makes that figure a derivation rather than an illustration | The witness's admission and eviction rules in §9.7.4.3; `17-persistence-and-storage.md` §17.17.4 |
| `LEAF_REPLACEMENT_GRACE` | 86400 s (24 h) | Set to the 24-hour PCS Update interval §9.7.3 recommends, the cadence at which an identity replaces a leaf in an active context | §9.12 step 1a; the invariant of `03-identity.md` §3.2.1 |
| `CONTENT_RESOLUTION_RETRY_WINDOW` | 300 s (5 min) | Set equal to the attestation-resolution staleness bound of §9.18.7, past which the same verifier already treats a key-event log as stale | §9.7.1's content-signature freshness bound |
| `MAX_PENDING_CONTENT_PER_SENDER` | 64 | A party sending content under fabricated key identifiers fills a bounded buffer and nothing more | §9.7.1's content-signature freshness bound |

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
