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

**What no existing standard covers:** Agents as first-class protocol participants with formalized trust semantics, one-agent-per-person-per-context constraints, context-bound agents that cannot cross at the protocol level, trust as identity + capability pairs applied to autonomous agents, non-fungible cross-platform identity attestations with shadow identity claiming, protocol-level bridge connectors with provenance-tracked content attribution, and all of this framed as infrastructure for generated/ephemeral apps. This is the novel contribution of SCP.
