# 11. Prior Art

| Component | Existing Standard/Technology | SCP Relationship |
|---|---|---|
| Identity | DID (W3C) | Build on directly |
| Capability tokens | UCAN | Build on directly |
| Key custody | Passkeys, WebAuthn, Secure Enclave | Delegate custody to |
| Transport | Matrix, libp2p, Nostr | Build on / interop |
| Data sovereignty | Solid, AT Protocol PDS | Informed by, evaluate |
| Federated contexts | ActivityPub, Matrix rooms | Informed by |
| Access control | RBAC (decades old) | Standard application |
| Auth delegation | OAuth, GNAP | Informed by |
| Local AI-tool wiring | MCP (Model Context Protocol) | Agent-level integration |
| P2P transport + NAT traversal | Hyperswarm (Holepunch) | Informed by; architecturally distinct |

### Holepunch / Hyperswarm

**Holepunch** (github.com/holepunchto) builds open-source P2P infrastructure: Hyperswarm (DHT + UDP hole punching), Hypercore (append-only signed logs), Keet (production P2P encrypted chat), Pear (P2P app runtime). Keet is a shipping product — proof that zero-server P2P chat works at scale.

**Similar:** Zero-server thesis. DHT for discovery. NAT traversal as first-class concern. E2E encryption.

**Different:**
- **Transport coupling.** Hyperswarm IS the transport. SCP is transport-agnostic (17 adapters, §10.5). Hyperswarm could be one adapter.
- **Trust.** Hyperswarm: IP+port reputation. SCP: DID + UCAN + context governance (§3, §4, §5.3).
- **Group membership.** MLS in SCP enforces cryptographically. Hyperswarm: app-level.
- **Context isolation.** SCP's security boundary (§5). No Hyperswarm equivalent.
- **Relay vs direct P2P.** SCP: async via relays (store-and-forward). Hyperswarm: synchronous direct connections.
- **Provenance.** SCP: protocol-level (§7.7). Hypercore: data-structure level.

**Why not use Hyperswarm directly:** Transport independence tenet. Different trust model. SCP relay architecture enables async delivery, multi-relay suppression resistance (§9.9.2), bridge fallback.

**What SCP borrows conceptually:** DHT-integrated hole punching as a reachability primitive (§10.12.3). Proof that zero-server P2P works at production scale (Keet).

**What no existing standard covers:** Agents as first-class protocol participants with formalized trust semantics, one-agent-per-person-per-context constraints, context-bound agents that cannot cross at the protocol level, trust as identity + capability pairs applied to autonomous agents, non-fungible cross-platform identity attestations with shadow identity claiming, protocol-level bridge connectors with provenance-tracked content attribution, and all of this framed as infrastructure for generated/ephemeral apps. This is the novel contribution of SCP.
