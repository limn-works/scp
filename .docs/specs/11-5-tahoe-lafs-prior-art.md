## 11.5 Tahoe-LAFS

**Tahoe-LAFS** (Tahoe Least-Authority File Store) is an open-source, decentralized, cryptographically secure distributed file system created by Zooko Wilcox-O'Hearn and Brian Warner. Originally developed at allmydata.com (2006-2009) as a commercial backup service, it was released as open-source software and became the reference implementation of provider-independent, capability-secured storage. The foundational paper was presented at ACM StorageSS 2008 (Wilcox-O'Hearn & Warner, "Tahoe: the least-authority filesystem," Proceedings of the 4th ACM International Workshop on Storage Security and Survivability, 2008, pp. 21-26). Tahoe-LAFS is the most complete real-world application of object-capability security principles to distributed storage, and the intellectual ancestor of the capability-based authorization model that SCP inherits through UCAN.

### 11.5.1 The Principle of Least Authority

The "LAFS" in the name is literal: the system is designed around the principle of least authority (POLA) — every component has exactly the minimum power required for its function, enforced by cryptography rather than policy. Storage servers cannot read the data they store. Clients cannot modify data they have only read access to. Repairers can reconstruct missing shares without decrypting content. The system's security properties hold even if every storage server is adversarial.

This is the same design principle that informs SCP's relay architecture. Both protocols begin from the premise that infrastructure operators should have no access to the data they handle:

| Principle | Tahoe-LAFS | SCP |
|-----------|------------|-----|
| **Operator access to content** | None — servers store encrypted, erasure-coded shares | None — relays store encrypted MLS blobs |
| **Enforcement mechanism** | Client-side encryption + capability URIs | MLS group keys + UCAN tokens |
| **What operators see** | Opaque ciphertext shares indexed by storage index | Opaque ciphertext indexed by pseudonym-derived routing IDs (§9.10.2) |
| **Can operators deny service?** | Yes (availability threat) | Yes (availability threat) |
| **Can operators read content?** | No (encryption at client) | No (MLS encryption at sender) |
| **Can operators modify content?** | Detectable (Merkle hash verification) | Detectable (MLS authenticated encryption) |
| **Redundancy model** | k-of-n erasure coding across storage nodes | Multi-relay publishing for suppression resistance (§9.9.2) |

The shared insight: the math enforces access control, not the infrastructure. Infrastructure is treated as an adversarial commodity. This is "provider-independent security" in Tahoe's terminology and "dumb-pipe relays" in SCP's.

### 11.5.2 Capability Model

The capability model is the centerpiece of Tahoe-LAFS and the most important comparison with SCP. In Tahoe, a capability (cap) is a cryptographic URI string that simultaneously provides both **location** (where to find the data on the grid) and **identification** (proof that the retrieved data is authentic). Possessing the cap IS the authorization — there is no access control list, no identity check, no server-side permission enforcement. The cap is an unforgeable bearer token.

#### Capability Types

Tahoe defines 13 capability types across two categories (filecaps and dircaps), organized in a derivation hierarchy where stronger capabilities can derive weaker ones (called "diminishing") but never the reverse:

**Immutable files:**

| Cap Type | URI Prefix | Contains | Grants |
|----------|-----------|----------|--------|
| Read-cap | `URI:CHK:` | 16-byte AES read key + SHA-256 hash of URI Extension Block | Decrypt and read file content |
| Verify-cap | `URI:CHK-Verifier:` | Storage index + UEB hash (no read key) | Verify integrity of ciphertext shares without reading plaintext |
| Literal | `URI:LIT:` | File content inline (files <= 55 bytes) | Read (content embedded in cap itself) |

The read key is a 16-byte AES key. The storage index (the address used to locate shares on the grid) is derived by hashing the read key with SHA-256d and a single-purpose tag. This means: knowing the read key lets you derive the storage index (and thus locate + decrypt the file), but knowing the storage index does not let you derive the read key (and thus you can verify shares but not decrypt them). The one-way derivation chain is:

```
read_key → SHA-256d → storage_index → (locate shares, verify integrity)
read_key → AES-CTR decrypt → plaintext
```

**Mutable files (SSK — from Freenet's "Sub-Space Keys"):**

| Cap Type | URI Prefix | Contains | Grants |
|----------|-----------|----------|--------|
| Write-cap | `URI:SSK:` | 16-byte AES write key + verification key hash | Read + write (update file content) |
| Read-cap | `URI:SSK-RO:` | 16-byte AES read key + verification key hash | Read (decrypt current version) |
| Verify-cap | `URI:SSK-Verifier:` | Storage index + verification key hash | Verify integrity without reading |

Mutable files add RSA-2048 for asymmetric signing. The derivation chain is:

```
RSA-2048 private key (signature key)
  → hash + truncate to 16 bytes → write_key (encrypts the RSA private key in shares)
    → hash + truncate to 16 bytes → read_key (encrypts/decrypts file content)
      → hash + truncate to 16 bytes → storage_index (locates shares on grid)

RSA-2048 public key (verification key)
  → SHA-256 → verification_key_hash (included in all URIs for integrity binding)
```

Each derivation step is a one-way hash truncation. A write-cap holder can derive the read-cap and verify-cap. A read-cap holder can derive only the verify-cap. A verify-cap holder can verify share integrity but neither read nor write. The write key encrypts the RSA private key within shares; the read key encrypts the file content. This separation means the RSA private key (and thus write authority) is protected by a different symmetric key than the content itself.

**Directories** mirror the file hierarchy: mutable directory write-cap (`URI:DIR2:`), read-cap (`URI:DIR2-RO:`), verify-cap (`URI:DIR2-Verifier:`), plus immutable variants. Directories are implemented as mutable files whose content is a serialized mapping of child names to child capabilities. Read-only access to a directory is transitively read-only — you cannot extract write-caps for children from a read-only directory cap.

#### The Repaircap: Least Privilege in Action

Tahoe's repair mechanism demonstrates the capability model's granularity. A repairer receives a cap that contains enough information to download shares, verify their integrity, reconstruct missing shares via erasure coding, and upload replacements — but cannot decrypt the file content. The repairer works entirely on ciphertext. This is the principle of least authority applied to infrastructure maintenance: the entity responsible for data durability has no access to data confidentiality.

### 11.5.3 Capability Model Comparison: Tahoe-LAFS vs SCP UCAN

Both Tahoe-LAFS and SCP use capability-based authorization where the bearer token (not an identity lookup) determines access. But the capability models differ fundamentally in structure, delegation, lifecycle, and scope.

| Dimension | Tahoe-LAFS Capabilities | SCP UCAN Tokens |
|-----------|------------------------|-----------------|
| **Representation** | Cryptographic URI string (`URI:CHK:...`, `URI:SSK:...`) | Signed JWT (JSON Web Token with `ucv`, `iss`, `aud`, `att`, `exp` fields) |
| **What it encodes** | Encryption key + content hash (location + identification) | Issuer DID + audience DID + capability set + expiration + proofs |
| **Bearer semantics** | Pure bearer — anyone with the URI string has access | Audience-bound — only the `aud` DID can exercise the capability |
| **Identity binding** | None — capabilities are anonymous | DID-bound — issuer and audience are cryptographically identified |
| **Delegation** | None — you share the cap string, granting full access at that level | Native — `prf` (proof) field chains delegations; each link is a signed JWT |
| **Attenuation** | One direction only: write → read → verify (diminishing) | Arbitrary: any capability subset, custom resources, narrower scope |
| **Time-bounding** | None — caps are permanent while the data exists | Native — `exp` (expiration) and `nbf` (not-before) fields |
| **Revocation** | Impossible — the cap is the key, and you cannot un-share a key | Revocation records (§7.3) checked at verification time |
| **Scope** | Single file or directory | Context-scoped: `scp:ctx:{context_id}/{resource}:{action}` |
| **Governance** | None — no concept of rules governing capability exercise | Full governance model: 28 action types, pluggable engines (§5.9) |
| **Accountability** | None — caps are anonymous, no audit trail of who used them | Full — every action signed by a DID, recorded in event logs |
| **Composability** | File-level only | Protocol-wide: identity + capability + context + governance |

**The fundamental divergence:** Tahoe capabilities are static and anonymous. Once you have a read-cap, you have read access forever, and no one can tell who is reading. UCAN tokens are dynamic and identified. They expire, they can be revoked, they chain through identified delegators, and every exercise is attributable to a specific DID.

This reflects the different problem domains. Tahoe secures data at rest — files on a grid. The threat model is the storage provider reading or modifying your files. Anonymity is a feature: the cap proves you are authorized without revealing who you are. SCP secures interaction — communication within governed contexts. The threat model includes unauthorized agents, capability escalation, and unattributable actions. Identity is a feature: the UCAN proves both that you are authorized AND who you are.

Both inherit from the object-capability tradition (Dennis & Van Horn 1966, Mark Miller's E language, erights.org). The intellectual lineage runs: object-capability theory → Tahoe-LAFS (cryptographic capabilities for storage) → UCAN (cryptographic capabilities for authorization delegation) → SCP (capabilities embedded in a governance and identity framework). Tahoe proved that cryptographic capabilities work for decentralized access control without ACLs. UCAN added the delegation, attenuation, and identity-binding that real-world authorization requires. SCP embedded UCANs in a context-governed, MLS-encrypted interaction protocol.

### 11.5.4 Provider-Independent Security

Tahoe-LAFS coined the term "provider-independent security" to describe a property that goes beyond encryption:

> "The service provider never has the ability to read or modify your data in the first place: never."

This is not just "data is encrypted." It means:

1. **Confidentiality** — the provider cannot read your data (AES encryption, key held only by client)
2. **Integrity** — the provider cannot modify your data undetectably (Merkle hash trees, cap-embedded hashes)
3. **Unforgeability** — the provider cannot create data that appears to be yours (RSA signatures for mutable files, content-hash binding for immutable files)

The provider can deny service (refuse to store or serve shares). It cannot do anything else. All three properties derive from cryptographic constructions that the client performs independently of the server.

SCP achieves the same three properties through different mechanisms:

| Property | Tahoe-LAFS Mechanism | SCP Mechanism |
|----------|---------------------|---------------|
| **Confidentiality** | AES-128-CTR, key in client-held capability | MLS group key (AES-128-GCM), distributed via MLS key schedule |
| **Integrity** | Merkle hash trees + SHA-256d, roots embedded in caps | MLS authenticated encryption (AEAD) + event log Merkle trees |
| **Unforgeability** | RSA-2048 signatures (mutable files), content-hash binding (immutable) | Ed25519 signatures on MLS messages + UCAN chain verification |
| **Relay/server access** | Sees encrypted shares + storage index | Sees encrypted blobs + pseudonym-derived routing IDs |
| **Key management** | Embedded in capability URIs (no separate key distribution) | MLS key schedule (ratcheting, forward secrecy, post-compromise security) |

The deepest parallel is the design philosophy: both protocols treat the infrastructure layer as an adversarial commodity service. Tahoe's storage servers are interchangeable, untrusted, and unaware of what they store. SCP's relays are interchangeable, untrusted, and unaware of what they forward. The client (Tahoe) or participant (SCP) performs all security-critical operations.

Where SCP extends beyond Tahoe: MLS provides forward secrecy and post-compromise security — properties that Tahoe's static encryption keys cannot provide. Tahoe's AES key for a file is permanent; if it leaks, all past and future access to that file is compromised. MLS ratchets keys with each epoch, so compromise of a current key does not expose past messages, and removal of a compromised member restores confidentiality for future messages. This difference reflects storage (static) vs communication (evolving group membership).

### 11.5.5 Erasure Coding and Redundancy

Tahoe distributes each file across multiple storage nodes using erasure coding. The default parameters are:

- **k = 3** — minimum shares needed to reconstruct the file
- **N = 10** — total shares created
- **H = 7** — minimum independent servers required for upload success ("servers of happiness")
- **Expansion factor: 3.3x** — each file consumes 3.3x its plaintext size in storage

The pipeline: plaintext → AES-CTR encryption → segmentation (128 KiB default) → erasure coding per segment → one block per segment per share → distribution across servers. Each share gets one block per segment, plus Merkle hash trees for verification.

The erasure coding algorithm (zfec, based on Rizzo's FEC) means any k-of-N shares suffice for reconstruction. Up to (N - k) = 7 servers can fail simultaneously without data loss. The system can tolerate the loss of any 70% of its storage nodes.

**Comparison with SCP's multi-relay architecture (§9.9.2):**

| Dimension | Tahoe-LAFS Erasure Coding | SCP Multi-Relay Publishing |
|-----------|--------------------------|---------------------------|
| **Purpose** | Data durability — survive storage node failure | Message availability — survive relay failure or censorship |
| **Mechanism** | k-of-N erasure coding (zfec) | Full message replication to multiple relays |
| **Redundancy** | Encoded fragments — any k of N suffice | Full copies — any 1 of M relays suffice |
| **Expansion cost** | 3.3x storage (tunable via k/N ratio) | Mx storage and bandwidth (M = number of relays) |
| **Failure tolerance** | (N - k) simultaneous node failures | (M - 1) simultaneous relay failures |
| **Reconstruction** | Client downloads k shares, decodes | Client reads from first available relay |
| **Suppression resistance** | High — attacker must compromise >70% of nodes | High — attacker must compromise all relays (§9.9.2) |
| **What's distributed** | Encoded ciphertext fragments | Complete encrypted messages |

Tahoe's approach is more storage-efficient (3.3x vs Mx). SCP's approach is simpler (no erasure coding, no multi-share reconstruction). The difference reflects their domains: Tahoe must store large files durably for long periods, making encoding efficiency critical. SCP must deliver messages reliably in real time, making simplicity and latency critical. Erasure coding adds reconstruction latency; full replication provides instant availability from any relay.

Tahoe's redundancy model offers one insight relevant to SCP: k-of-N encoding could improve SCP's relay-layer efficiency for large payloads (blob storage, file attachments). Instead of replicating a 100 MB file to 3 relays (300 MB total), erasure coding to 3-of-10 across 10 relays would use 330 MB but survive 7 relay failures instead of 2. This is an optimization opportunity, not a design necessity.

### 11.5.6 Convergent Encryption

Tahoe's convergent-key method computes the file's encryption key deterministically from its content:

```
encryption_key = SHA-256d(tag || encoding_params || convergence_secret || file_contents)[:16]
```

If two clients upload the same file with the same convergence secret, they produce the same ciphertext and the same capability URI. The file is stored once on the grid — deduplication without the server ever seeing the plaintext.

The convergence secret is a per-client random value generated on first startup. By default, each client's files converge only with their own previous uploads. Sharing the convergence secret between clients enables cross-client deduplication but introduces two attacks:

1. **Confirmation-of-a-file attack** — an adversary who knows both the convergence secret and a candidate plaintext can check whether that file exists on the grid (compute the expected cap, attempt download).
2. **Learn-the-remaining-information attack** — if the adversary knows most of a file's content and the convergence secret, brute-forcing the remaining unknown bytes becomes an offline attack (no server interaction needed).

Tahoe also offers a random-key method (non-convergent) for applications where deduplication is less important than privacy against these attacks.

SCP has no equivalent of convergent encryption. MLS encryption keys are derived from the group key schedule, not from message content. Each message produces unique ciphertext even if the plaintext is identical. Deduplication is not a goal — in a communication protocol, message identity matters (the same text sent twice is two distinct messages with distinct timestamps and sequence numbers). Tahoe's convergent encryption is a storage optimization that is inapplicable to real-time communication.

### 11.5.7 Mutable Files and Versioning

Tahoe's immutable files are write-once: the capability is derived from the content, so changing the content changes the capability. Mutable files (SSK format) add updateability:

- **RSA-2048 keypair** — the private key signs updates, the public key verifies them
- **Sequence numbers** — 64-bit monotonic counter prevents rollback attacks
- **Two formats:** SDMF (Small Distributed Mutable Files, single segment, entire file downloaded for any read) and MDMF (Medium Distributed Mutable Files, 128 KiB segments, partial reads/writes)
- **Write coordination:** The "Prime Coordination Directive" warns that uncoordinated simultaneous writes can corrupt a file if competing versions exceed the erasure coding recovery threshold (S > N/k)
- **Per-server write enablers:** `H(write_enabler_master + server_nodeid)` — each storage server gets a unique authorization token, preventing cross-server impersonation

**Comparison with SCP event logs:**

| Dimension | Tahoe Mutable Files | SCP Event Logs (§8) |
|-----------|--------------------|--------------------|
| **Mutability model** | Replace-in-place (latest version wins) | Append-only (events accumulate) |
| **Signing** | RSA-2048 (single writer per file) | Ed25519 via MLS (multi-writer per context) |
| **Multi-writer** | Discouraged — "Prime Coordination Directive" warns of corruption | Native — MLS group membership defines write authority |
| **Versioning** | Sequence number (64-bit monotonic counter) | MLS epoch + generation + sequence triple |
| **Conflict resolution** | Last-writer-wins (no CRDT, no merge) | Ordered by MLS epoch (no conflict — append-only) |
| **Forward secrecy** | None — same RSA key for all versions | Yes — MLS key ratcheting per epoch |
| **Rollback prevention** | Sequence number check | Merkle tree inclusion proofs |
| **Write authorization** | Possession of write-cap (anonymous) | MLS membership + UCAN capability + governance check |

Tahoe's mutable files are a storage primitive — they provide a single mutable slot with integrity and confidentiality. SCP's event logs are a richer structure: append-only (no destructive update), multi-writer with cryptographic membership enforcement, embedded in a governance framework that controls who can append what.

### 11.5.8 Grid Architecture

A Tahoe grid consists of three node types:

1. **Introducer** — a coordination node that maintains the server roster. Servers announce themselves to the introducer; clients connect to receive the list of available servers. The introducer is a recoverable single point of failure: it is defined by a hostname and a private key, easily relocated. Once clients have the server roster, they maintain direct connections without the introducer.

2. **Storage servers** — user-space processes that store shares (encrypted, erasure-coded fragments). Servers perform no cryptographic operations — no decryption, no signature verification, no erasure coding. They are deliberately simple: accept shares, serve shares, manage leases. This simplicity is a security feature — the server has no capability that could be exploited to compromise data.

3. **Client nodes (gateways)** — the security-critical component. Clients perform all encryption, erasure coding, share distribution, Merkle tree computation, capability generation, and download reconstruction. Clients connect to every known server in a bi-clique topology. The client is the only component that handles plaintext or encryption keys.

Server selection uses consistent permutation: `HASH(storage_index + nodeid)` sorts servers into a deterministic, per-file order, ensuring even distribution across the grid. Nodes communicate over TCP using Foolscap (the original protocol) or HTTPS (default since v1.19).

**Comparison with SCP's architecture:**

| Dimension | Tahoe-LAFS Grid | SCP Relay + Node Architecture |
|-----------|----------------|------------------------------|
| **Discovery** | Introducer (centralized roster) | DHT + relay layer + DID document service endpoints (§3.10, §18) |
| **Infrastructure role** | Storage servers — store shares, serve shares, nothing else | Relays — receive blobs, deliver blobs, nothing else |
| **Client role** | All crypto + erasure coding + share management | All crypto + MLS + governance + capability validation |
| **Topology** | Bi-clique (every client → every server) | Subscription-based (participants subscribe to routing IDs on relays) |
| **Protocol** | Foolscap / HTTPS | WebSocket (primary) + 17 transport adapters (§10.5) |
| **Server intelligence** | Minimal — store/serve/lease | Minimal — receive/deliver/TTL |
| **Single point of failure** | Introducer (recoverable) | None — DHT + multiple relays + relay fallback list (§18.5.1) |
| **NAT traversal** | Requires Foolscap connection (bi-clique limited by NAT) | 4-tier reachability: port mapping, hole punching, bridge relay, domain TLS (§10.12) |

Both architectures share the principle that infrastructure nodes (storage servers / relays) are deliberately stupid. All security-critical logic lives in the client. The main architectural difference is discovery: Tahoe uses a centralized introducer (simple, but a single point of failure); SCP uses decentralized multi-layer resolution (more complex, but no single point of failure).

### 11.5.9 Zooko's Triangle

Zooko Wilcox-O'Hearn, the co-creator of Tahoe-LAFS, is also the originator of Zooko's triangle (2001) — the conjecture that no single naming system can simultaneously achieve all three properties:

1. **Secure** — names cannot be spoofed or hijacked
2. **Human-meaningful** — names are memorable and readable
3. **Decentralized** — names resolve without a central authority

This is the same naming trilemma discussed in §11.3.5 (GNS). The connection between Tahoe-LAFS and Zooko's triangle is not merely biographical — the same person who identified the fundamental naming problem also built a system that sidesteps it entirely. Tahoe capabilities occupy the "secure + decentralized" edge: they are cryptographic strings that no human will memorize, but they are unforgeable and resolve without any authority. Tahoe does not attempt human-meaningful naming — it delegates that to the directory layer, where users create named hierarchies from capability-addressed files.

SCP's DID approach makes the same trade-off: `did:dht:z6Mk...` strings are secure and globally unique but not human-meaningful. Like Tahoe, SCP compensates at the application layer (display names in DID documents, context-level naming). The parallel is exact: both systems choose cryptographic identifiers at the infrastructure layer and push human-readable naming to a higher layer.

| System | Secure | Human-meaningful | Decentralized | Compensation |
|--------|--------|-----------------|---------------|--------------|
| **Tahoe-LAFS caps** | Yes (cryptographic) | No (opaque URIs) | Yes (no authority) | Directory hierarchy with named children |
| **SCP DIDs** | Yes (self-certifying) | No (z-base-32 strings) | Yes (DHT-resolved) | Display names in DID documents, context naming |
| **DNS** | Weak (DNSSEC optional) | Yes | No (ICANN hierarchy) | — |
| **GNS** | Yes | Yes (petnames) | Yes (no authority) | Local only — not globally unique |
| **ENS** | Yes | Yes | Partial (requires Ethereum) | Blockchain as global state |

### 11.5.10 What SCP Borrows Conceptually

Three ideas flow directly from Tahoe-LAFS into SCP's design:

1. **Capability-based authorization without ACLs.** Tahoe proved that distributed systems can enforce access control using cryptographic bearer tokens rather than identity lookups or server-side permission lists. This is the foundation of SCP's UCAN model. The conceptual step from Tahoe caps to UCANs is: add identity binding (issuer/audience DIDs), add delegation chains (proof fields), add time-bounding (expiration), add revocation, add governance. But the core insight — the token IS the authorization, verified by cryptography not by asking a server — originates in this tradition.

2. **Provider-independent security.** The principle that infrastructure operators should have zero access to the data they handle. Tahoe applied this to file storage (servers cannot read files). SCP applies it to message delivery (relays cannot read messages). Same principle, different scope. In both cases, the client/participant performs all encryption and the infrastructure handles only opaque ciphertext.

3. **The math enforces access, not the infrastructure.** Tahoe's entire security model derives from the hardness of AES, SHA-256, and RSA — not from trusting servers to enforce permissions. SCP's security model derives from the hardness of AES-128-GCM (MLS AEAD), SHA-256 (Merkle trees, storage indices), and Ed25519 (signatures, DID binding) — not from trusting relays or governance servers. Both protocols are designed so that a fully adversarial infrastructure cannot compromise confidentiality or integrity. Only availability is at risk.

The intellectual lineage: object-capability theory (Dennis & Van Horn 1966) → E language (Mark Miller 1997) → Tahoe-LAFS (Wilcox-O'Hearn & Warner 2007) → UCAN (Fission/Brooklyn Zelenka 2021) → SCP. Each step adds structure: E added language-level enforcement; Tahoe added cryptographic enforcement for distributed storage; UCAN added delegation, attenuation, and identity binding; SCP added governance, group encryption, and context isolation.

### 11.5.11 Why SCP Diverges

Despite the shared intellectual heritage, Tahoe-LAFS and SCP solve fundamentally different problems. The divergences are not deficiencies in either system — they reflect different domains.

| Dimension | Tahoe-LAFS | SCP | Why Different |
|-----------|------------|-----|---------------|
| **Domain** | File storage (data at rest) | Communication (data in motion within governed contexts) | Storage is static; communication is dynamic with evolving group membership |
| **Capability lifecycle** | Permanent — a cap grants access as long as the data exists | Time-bounded — UCANs expire, can be revoked, are governance-scoped | Communication requires temporal control; file access is typically permanent |
| **Capability delegation** | None — share the URI string, that's it | Native — delegation chains with attenuation at each link | Communication requires scoped, auditable delegation; file sharing is simpler |
| **Identity** | None — capabilities are anonymous bearer tokens | Core — every action traces to a DID, attestation chains to human accountability | Storage can be anonymous; communication in governed contexts requires accountability |
| **Group communication** | None — Tahoe is single-user or share-the-cap | Native — MLS groups with add/remove/update, forward secrecy, post-compromise security | File storage does not require real-time group membership management |
| **Governance** | None — no concept of rules, roles, or permissions beyond read/write/verify | 28 governance action types, pluggable engines, capability ceilings (§5.9) | File storage is ungoverned; collaborative communication requires governance |
| **Forward secrecy** | None — static encryption keys per file | Yes — MLS key ratcheting per epoch | Static files do not benefit from key ratcheting; communication sessions do |
| **Conflict resolution** | Last-writer-wins for mutable files | Append-only event logs — no conflict by construction | File replacement is a valid operation; message history is immutable |
| **Transport** | Grid-specific (Foolscap/HTTPS between Tahoe nodes) | Transport-agnostic (17 adapters, §10.5) | File grids are a closed system; communication must bridge protocol worlds |
| **Agent model** | No concept of AI agents | First-class — agents are UCAN-bounded participants with human accountability chains | 2007 design predates the agentic paradigm entirely |
| **Provenance** | None beyond capability possession | Protocol-level — every action carries verifiable origin metadata (§24) | File access does not require provenance; agentic communication does |

**The sharpest difference:** Tahoe capabilities are anonymous and permanent. This is correct for file storage — you want a link to a file to work forever, and you do not need to know who is reading it. SCP's UCAN tokens are identified and ephemeral. This is correct for communication — you need to know who is speaking, you need to bound how long a delegation lasts, and you need to revoke access when group membership changes.

### 11.5.12 Least Authority, Zcash, and the Capability Lineage

Zooko Wilcox-O'Hearn's trajectory after Tahoe-LAFS traces the evolution of capability thinking:

- **2006-2009:** Co-created Tahoe-LAFS at allmydata.com with Brian Warner. Proved that cryptographic capabilities work for provider-independent distributed storage.
- **2011:** Founded **Least Authority Enterprises** in Boulder, Colorado — a security consulting firm that performed audits for privacy and transparency projects (GlobalLeaks, Ethereum, and others). The company name is a direct reference to the principle of least authority that underpins Tahoe-LAFS.
- **2016:** Co-founded **Zcash** (launched October 28, 2016) — a privacy-preserving cryptocurrency using zero-knowledge proofs (zk-SNARKs). Zcash applies the same principle at the transaction layer: the blockchain verifier never learns the transaction amounts or parties. Wilcox-O'Hearn served as CEO of the Electric Coin Company (Zcash's development organization) until December 2023.

The thread connecting these projects: **cryptographic enforcement of minimal authority.** Tahoe-LAFS applies it to storage (the server cannot read your files). Zcash applies it to transactions (the network cannot see your payments). SCP applies it to communication (the relay cannot read your messages). The common denominator is that the infrastructure layer is denied authority over the data it processes, enforced by mathematics rather than policy.

The direct intellectual lineage from Tahoe to UCAN runs through the broader object-capability community. Brooklyn Zelenka and the Fission team who created UCAN explicitly cite capability-based security principles. While UCAN was not derived from Tahoe-LAFS's code, it addresses the same fundamental question — "how do you authorize access in a decentralized system without a central authority?" — and arrives at the same answer: bearer tokens containing cryptographic material, where possession of the token is both necessary and sufficient for the authorized action.

### 11.5.13 References

- Wilcox-O'Hearn, Zooko & Warner, Brian. "Tahoe: the least-authority filesystem." *Proceedings of the 4th ACM International Workshop on Storage Security and Survivability (StorageSS '08)*, October 2008, pp. 21-26. doi:10.1145/1456469.1456474. Also: IACR Cryptology ePrint Archive, Paper 2012/524.
- Tahoe-LAFS project documentation: https://tahoe-lafs.readthedocs.io/
- Tahoe-LAFS source repository: https://github.com/tahoe-lafs/tahoe-lafs
- Tahoe-LAFS capability specification: https://tahoe-lafs.org/trac/tahoe-lafs/wiki/Capabilities
- Tahoe-LAFS file encoding specification: https://tahoe-lafs.readthedocs.io/en/latest/specifications/file-encoding.html
- Tahoe-LAFS mutable file specification: https://tahoe-lafs.readthedocs.io/en/latest/specifications/mutable.html
- Tahoe-LAFS architecture overview: https://tahoe-lafs.readthedocs.io/en/latest/architecture.html
- Tahoe-LAFS convergence secret: https://tahoe-lafs.readthedocs.io/en/latest/convergence-secret.html
- Wilcox-O'Hearn, Zooko. "Names: Distributed, Secure, Human-Readable: Choose Two." 2001. (Origin of Zooko's triangle.)
- Miller, Mark S. "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control." PhD thesis, Johns Hopkins University, 2006. (Foundation of the object-capability model.)
- Dennis, Jack B. & Van Horn, Earl C. "Programming Semantics for Multiprogrammed Computations." *Communications of the ACM* 9(3), March 1966, pp. 143-155. (Origin of capability-based security.)
- UCAN specification: https://github.com/ucan-wg/spec
