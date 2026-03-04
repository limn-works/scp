# 4. Agents

## 4.1 Core Principle

Humans and their bound agents are the only actors in the system. Every action on the protocol — every message, every tool invocation, every state change — is traceable to a human(s) as an action they took or their attributed agent took. There are no anonymous actors or unaccountable software participants.

## 4.2 Binding

Every agent is bound to its human through the DID document itself — the agent's signing key is a verification method (`#agent`) on the human's DID. Binding is structural, not an external proof: the DID document is the single source of truth for which key is the human's (`#active`) and which is the agent's (`#agent`). The binding is verifiable by any participant who resolves the DID.

- **Personal agents:** Bound to a single human. The common case. The human's DID document contains at most one `#agent` verification method.
- **Institutional agents:** Bound to multiple humans through shared governance (multi-sig, elected operators, organizational hierarchy). Structurally identical to personal agents; the difference is in who holds the keys and how revocation/control works. Institutions get one agent per context, the same as individuals — one seat per institution per table.

## 4.3 One Agent Per Person Per Context

At the protocol level, each human has exactly one agent per context. This is structurally enforced: a DID document contains exactly one `#agent` verification method. Verifiers reject DID documents with multiple `#agent` VMs. The agent can be arbitrarily capable internally — parallel execution, complex orchestration, sophisticated reasoning. The constraint is on presence: one seat per person per table.

Prevents: fleet-based force multiplication within a space, agent slot rental within a context, swarm attacks from a single identity, ambiguity in trust evaluation.

## 4.4 Bring Your Own Agent

The protocol defines how agents communicate and what capabilities they can exercise. It does not define what agents are internally. Users bring their own: models, configurations, logic, local infrastructure. A user running a frontier model and a user running a basic assistant both have one seat. The asymmetry in capability is acknowledged, not policed.

The protocol surfaces **agent capability metadata** — a standardized profile of what an agent can do — so other participants can evaluate it. Not the model name or implementation details, but a functional profile. Capability metadata distinguishes between:

- **Self-attested capabilities.** Claimed by the agent's human operator but not independently verified. Any agent can make these claims. Trust in the claim depends on trust in the claimant.
- **Challenge-verified capabilities.** Tested via the protocol's challenge-response mechanism (§7.3.4). A verifier issued a standard challenge suite; the agent passed. The metadata records what was verified, when, and by whom. Challenge-verified capabilities are validation, not trust — the test result is objective.

Contexts can require specific capability levels for admission. "This context requires challenge-verified prompt injection resistance" is a mechanical admission check, not a judgment call.

## 4.5 The Human-Agent Pair

The fundamental unit of participation in SCP is not the agent alone — it is the human-agent pair. The human is the root of identity, trust, and accountability. The agent is how the human is present at the protocol level. Neither is complete without the other: an agent without a human binding is unaccountable; a human without an agent has no protocol-level presence.

This pairing is what the protocol provides. At the protocol level, the agent acts. At the trust level, the human is accountable. Other participants evaluate both: "Do I trust this person?" and "Do I trust what their agent can do?" These are separate questions with a single answer — the trust function (§7.1) evaluates identity and capability together.

The human and agent share a single DID but their actions carry distinct provenance. Messages signed with `#active` are human-direct; messages signed with `#agent` are agent-autonomous. This distinction is structural — verifiers can determine provenance from the signing key alone, without out-of-band metadata. The human can always act directly through `#active`, and the agent acts through `#agent`. The human decides what the agent does — from full autonomy to direct manual control — and that decision is local, outside protocol scope.

What this means for the ecosystem:

- **One actor model.** Every protocol action has the same structure: an agent acts, bound to a human, within a context. No bifurcation between "agent actions" and "human actions." This keeps the protocol simple and trust evaluation uniform.
- **Agent capability is a spectrum.** A passthrough agent that forwards human keystrokes is valid. A fully autonomous agent that acts on its own judgment is valid. The protocol treats both identically — the difference is in the human's local configuration, not in the protocol's evaluation.
- **The minimum viable agent is trivial.** A user doesn't need to "set up an agent" any more than they need to "set up TCP." The simplest agent can be generated, embedded in an app, or provided as a default. The protocol requires the pairing to exist, not that it be sophisticated.

## 4.6 Agents Are Consumers, Not Enforcers

Human-bound agents are **protocol consumers** — the same identity as their human, distinguished only by verification method (`#agent` vs `#active`), but consumers nonetheless. They use apps. They use context tools. They interact with contexts through the protocol. They have zero responsibility for enforcing protocol rules.

The protocol enforces itself — through cryptography (encryption-as-access-control, key tree exclusion for blocks, capability token validation) and through the SDK that builders use to construct conformant apps. Agents do not enforce blocking, role permissions, capability ceilings, or any other protocol rule. The protocol and its cryptographic guarantees handle enforcement. Apps built on the SDK inherit those guarantees. Agents and humans consume those apps.

This distinction matters because SCP is designed for a world of generated, ephemeral clients. Any enforcement that depends on agent or client behavior is not enforcement — it's a suggestion that non-conformant software can ignore. Protocol guarantees must be cryptographic or structural, never behavioral.

A separate class of agents exists outside this context: **builder agents** — the LLMs and AI systems that generate apps and services on top of SCP using the SDK. These are developers, not protocol participants. They are responsible for constructing software; human-bound agents are responsible for nothing beyond using it.

## 4.7 Context-Bound at Protocol Level

An agent in Context A has no protocol-level awareness of or connection to the same human's agent in Context B. At the protocol level, they are separate instances. They share no state through the network.

The human coordinates locally. On the user's machine, agents share state freely, coordinate, plan across contexts. The protocol only governs what touches the network. Each agent only operates within its own context.

This eliminates: cross-context infection via agent memory, runaway agent coordination at the protocol level, the need for bridging rate limits, metastatic growth patterns through agent connections.

**No direct agent-to-agent primitive.** The protocol does not and will not include a mechanism for agents to contact agents they share no context with. This was considered in depth (see planning-session-03.md for the full analysis, planning-session-06.md §2 for the rejection rationale) and rejected. The core reasoning: context isolation is the security boundary, and any mechanism that lets agents bypass it — even a "governed" one with rate limits and trust evaluation — reintroduces the attack surface isolation was designed to eliminate. Cross-context interaction uses tool interfaces (§6.2) for asymmetric service calls, multi-parent child contexts (§5.13) for symmetric collaboration, and standing bilateral contexts (§5.12.6) for persistent direct communication. All three require existing context membership or human facilitation. Agents that need new relationships require their humans to arrange them.

## 4.8 Agent Fleet

A human can be in many contexts, each with one agent configured for that context. The human is multiplied across the system but singular within any space. The rate-limiting surface is how many contexts a person participates in simultaneously, not how many agents they have in one room.

The number of contexts a person can participate in may be an earned resource — new identities start limited, earn more through history, reputation, and behavior. The earned capacity algorithm is an open design question — see the Sybil resistance entry in `.docs/specs/00-open-questions.md` for the full gap analysis and classification (P0, security-critical, Phase 2+).
