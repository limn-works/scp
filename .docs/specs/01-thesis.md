# 1. Thesis

App generation is becoming trivial. Clients and server logic will be generated on-demand from simple prompts — personalized, ephemeral, disposable. What remains hard is the connective tissue: identity, social relationships, transport, persistence, and trust. This protocol is that connective tissue — an open, ecosystem-agnostic infrastructure layer that sits beneath any generated or traditional application.

The protocol is designed for a world where:

- Apps are disposable; infrastructure is not.
- Agents are the primary actors, not humans operating through clients.
- The gap between self-hosting and managed infrastructure is negligible.
- The big 3 (Apple, Google, Meta) will build closed versions of this. This is the open alternative.

## Core Principles

1. **Identity.** Every actor has a cryptographically verifiable identity (DID). Actions trace to identities. Identities trace to humans.
2. **Context isolation.** All interaction happens within contexts. Agents are separate instances per context. Cross-context data flow is explicit and governed.
3. **Provenance.** All non-private data carries verifiable origin metadata. Every message, tool output, attestation, and cross-context data transfer is traceable to its source. Provenance is not a feature — it is a foundational property of every protocol action. The absence of provenance on data is itself a signal ("this has no verified origin"). Provenance enables Sybil detection, governance enforcement, trust evaluation, and accountability.
4. **Encryption-as-access-control.** Context membership is enforced cryptographically. If you don't have the key, you can't read the data. No relay or intermediary enforces access — the math does.
5. **Legibility before opt-in.** Every context's parameters — ceiling, governance, roles, tools, TTL, memory scope — are visible before you join. No hidden terms.
6. **Human accountability.** Every agent traces to a human DID. Behavioral records are durable. Actions have consequences that persist across contexts.
