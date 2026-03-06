# 15. Regulatory Compliance

The protocol is designed compliance-first and privacy-first. These are core ethos, not afterthoughts.

**Obligations fall on protocol users.** SCP is an open protocol specification, not a service. The protocol does not process data, host content, or operate infrastructure. Entities that build on SCP — app developers, relay operators, managed infrastructure providers, bridge operators — bear the regulatory obligations appropriate to their role. The protocol provides the tools to meet those obligations.

**Privacy by design:**

- **Encryption-as-access-control (§10.5)** means content is end-to-end encrypted. Relay operators cannot read content. This is a structural privacy guarantee, not a policy.
- **Identity private state (§3.7)** is encrypted to the owner's keys. Personal data (block lists, preferences, graph visibility) is not accessible to any other party.
- **Context metadata transparency (§5.7)** lets users make informed decisions before participating. No dark patterns at the protocol level.
- **DID-based identity (§3.1)** is self-sovereign. No identity provider holds user data.

**GDPR and data portability:**

- **Right to erasure.** A user can revoke their DID, revoke all attestations, and leave all contexts. Their identity private state is encrypted and under their control. The protocol supports erasure at three levels:

  1. **Ephemeral contexts (§5.10/§5.11)** are the protocol-level data minimization mechanism. Ciphertext is deleted on relays, encryption keys are destroyed, and all participants purge event data. This is protocol-enforced deletion — no data survives the context's TTL.
  2. **Local deletion in any context.** Participants MAY purge stored event data at any time while retaining the Merkle leaf hash for chain integrity. The hash proves an event existed at a position; the content is gone. This satisfies GDPR Art.17 obligations for the deleting node's storage.
  3. **The protocol does not propagate deletion requests to other participants.** Each node controls its own storage. This is inherent to decentralized systems — the same model as Signal, Matrix, and email. GDPR obligations apply per data controller, not across the network.

  Content authored in contexts remains on other participants' nodes (attributed to a now-revoked DID). Apps and context governance can implement content deletion policies; the protocol provides the identity revocation primitive.
- **Right to data portability.** Protocol state (membership, roles, attestations, participation records) is inherently portable — it's bound to the user's DID, not to any service provider. App state portability depends on the app (§8.3).
- **Data minimization.** Protocol state is minimal by design (§10.3). The protocol collects and stores the minimum data needed for its function.

**Content moderation (EU Digital Services Act, etc.):**

- Content moderation is a context governance responsibility, not a protocol responsibility. Contexts define their own rules, enforce them through roles and consequence mechanisms, and are governed by accountable identities.
- The protocol provides the tools for moderation (role-based permissions, consequence mechanisms, governance models, member ejection) but does not mandate specific content policies. Different contexts have different standards — this is by design.
- Managed infrastructure providers (relay operators, hosting services) may have additional obligations under local law. The protocol's encryption model means relay operators have limited ability to moderate content they can't read — this is a feature for privacy and a tension for compliance that operators must navigate based on their jurisdiction.
- **Relay vs. context as regulatory surface.** Relays handle opaque encrypted blobs and are not positioned to be classified as content intermediaries — they are more analogous to encrypted storage or transport providers. Content moderation obligations, if they materialize, are expected to apply at the **context** level, where content is legible and governance structures exist to enforce policies. This legal argument has not been tested in any jurisdiction; the protocol's design assumes it but does not depend on it.

**The boundary:** The protocol is responsible for providing privacy-preserving, sovereignty-respecting infrastructure with the tools needed for compliance. The protocol is not responsible for the compliance decisions of entities that build on it. This is the same boundary that TCP/IP, HTTP, and email operate under — the protocol enables, the users of the protocol are responsible.
