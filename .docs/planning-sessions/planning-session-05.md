# SCP Planning Session 05 — Cryptographic Security Hardening

**Date:** February 21, 2026
**Scope:** MITM prevention, forgery prevention, replay prevention, relay threat model, key lifecycle, forward secrecy, transport security
**Artifacts modified:** `.docs/specs/` (expanded §9 + modifications to §3, §5.10, §5.11, §10.4, §10.5, §16), `sketch.md` (new security APIs), `architecture.md` (security annotations)

---

## How This Session Started

The question was: **how does SCP prevent man-in-the-middle attacks, message forgery, and replay attacks?**

The honest answer before this session: the spec had strong local security (MLS encryption, UCAN tokens, Merkle logs, Ed25519 signatures) but significant gaps in global security — the defenses that protect the protocol across trust boundaries. Section 9 covered application-layer threats (spoofing, poisoning, Sybil) but did not address cryptographic protocol security.

---

## 1. Security Audit: What Was Missing

### Systematic gap analysis across attack classes:

| Attack Class | Before This Session |
|---|---|
| MITM on DID resolution | Not addressed. No specification of how Alice verifies she has Bob's real public key. |
| MITM on relay discovery | Not addressed. No specification of how relay lists are authenticated. |
| MITM on key exchange | Partially addressed. MLS handles group key distribution, but the spec didn't document the mapping between MLS concepts and SCP concepts. |
| Replay attacks | Not addressed. No nonce, timestamp validation, or deduplication mechanism specified. |
| Relay equivocation | Not addressed. Nothing prevented a relay from showing different event histories to different clients. |
| Cross-relay consistency | Not addressed. No mechanism for detecting conflicting relay state. |
| Key lifecycle | Not specified. No formal specification for key generation, distribution, rotation, destruction, or compromise recovery. |
| Forward secrecy / PCS | Not documented. MLS provides these properties, but the spec didn't state the guarantees or the SDK requirements. |
| Transport security | Not specified. No TLS requirements stated. |
| Message ordering | Partially addressed. Event logs were "signed and sequenced" but no validation rules specified. |

### What was already strong:

- **Encryption-as-access-control** (§10.5) — solid architecture. Relays are protocol-unaware, all access control is cryptographic.
- **UCAN capability tokens** — cryptographic delegation chains, per-capability revocation.
- **Merkle event logs** — append-only, signed, verifiable. Good foundation for integrity.
- **Ed25519 signatures** — on all protocol actions. Good foundation for non-repudiation.
- **Sybil resistance** (§9.3) — three-layer defense (device attestation, earned capacity, context-level thresholds).
- **13 identified threat vectors** (§9.2) — comprehensive application-layer threat analysis.

---

## 2. What MLS (RFC 9420) Provides

MLS is not just "group encryption." It's a complete secure group messaging protocol with specific security properties that map directly to SCP needs.

### Properties SCP inherits from MLS:

**Forward secrecy.** Epoch-based key ratcheting. After a Commit message advances the group to a new epoch, old epoch key material is deleted. Even if a member's current key state is compromised, messages from past epochs cannot be decrypted. This is the cryptographic guarantee behind ephemeral memory scope (§5.11) — destroying the MLS group state makes all context content physically unreadable.

**Post-compromise security (PCS).** The Update proposal mechanism. After a member sends an Update (generating fresh HPKE key pair and ratcheting their tree path), any previous compromise of that member's state becomes useless for future messages. This limits the damage window of key compromise.

**Authenticated key exchange.** MLS Welcome messages are HPKE-encrypted to the new member's KeyPackage. Only the intended recipient can decrypt the group secrets. The KeyPackage is signed by the member's identity key, so the inviter can verify they're adding the correct person.

**Transcript consistency.** TreeSync ensures all members agree on group state (membership, epoch, ratchet tree). Fork detection is built in — if two members have inconsistent group states, MLS's consistency checks will detect it.

**Per-message authentication.** MLS PrivateMessage format includes a membership_tag HMAC that proves the sender is a group member with the correct epoch secrets. This is an inner authentication independent of SCP's outer Ed25519 envelope signature.

**Generation numbers.** Per-sender incrementing counter. Recipients can detect message gaps (possible suppression) and reject messages with already-seen generation numbers (exact replays).

### Properties MLS does NOT provide:

**DID verification.** MLS delegates identity verification to an "Authentication Service" (AS). In SCP, the AS is DID resolution + UCAN validation. MLS trusts whatever the AS says — if the AS is wrong (compromised DID resolution), MLS can't help.

**Relay honesty.** MLS's "Delivery Service" (DS) is explicitly untrusted for content but can suppress messages, delay delivery, or serve different views to different members. MLS has no mechanism to detect these attacks.

**Timestamp-based replay rejection.** MLS uses logical ordering (generation numbers), not physical time. A relay that replays a message with a valid generation number from a past epoch (but presents it alongside appropriate epoch key material) could potentially confuse a client. SCP needs timestamp-based bounds on top of MLS.

**Multi-relay consistency.** MLS assumes a single DS. SCP uses multiple relays for redundancy. MLS has no concept of cross-relay consistency.

---

## 3. What did:dht Provides

The single most important security property of did:dht: **self-certification.**

The DID string itself is the z-base-32 encoding of the Ed25519 public key. When Alice resolves Bob's DID, she gets a DID document from the Mainline DHT. She verifies the document by:
1. Checking that the BEP44 record is signed by the key embedded in the DID
2. Checking the sequence number (prevents stale records)

If the verification passes, Alice knows the DID document is authentic. No trusted third party. No certificate authority. No DNS. The DID IS the public key, so there's nothing for a MITM to substitute.

**The question shifts from "is this the right key?" to "is this the right DID?"** — which is an out-of-band verification problem. This is where Key Continuity Verification (safety numbers) comes in.

**did:web does NOT have this property.** The server resolving did:web can serve any DID document. DNS hijacking, server compromise, or CA compromise all enable MITM. This is the fundamental reason did:web is a v1 stepping stone, not the target method.

---

## 4. The Defense Layer Architecture

We organized the security hardening as six defense layers, each addressing a specific class of attacks at a specific trust boundary.

### Why layers, not a flat list:

Each layer builds on the one below it. Layer 0 (primitives) provides the cryptographic tools. Layer 1 (identity) uses those tools to establish trust roots. Layer 2 (group keys) uses identity verification to bootstrap encrypted groups. Layer 3 (messages) uses group encryption for integrity and replay prevention. Layer 4 (relays) uses message-level security to detect relay misbehavior. Layer 5 (metadata) honestly documents what the lower layers cannot protect.

This structure makes it clear where each defense lives and what it depends on. It also makes gaps visible — if a layer is missing, everything above it is weakened.

### Layer 0: Cryptographic Primitives

**Decision: single ciphersuite for v1.**

- Ed25519 for all signatures (RFC 8032)
- MLS ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
- HPKE (RFC 9180) for DID-to-DID encryption: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
- SHA-256 for Merkle trees (Certificate Transparency style, RFC 6962)
- Envelope signature binds all fields: `SHA256(context_id || sender_did || epoch || generation || timestamp || payload_hash)`

**Rationale for single ciphersuite:** Ciphersuite negotiation adds complexity and attack surface (downgrade attacks). For v1, one ciphersuite means every implementation uses the same algorithms. Future versions may add negotiation.

### Layer 1: Identity Verification

**Key decisions:**

- did:dht is self-certifying → MITM on DID resolution is impossible given the correct DID
- did:web requires TOFU + TLS pinning + key change alerts (v1 stepping stone only)
- Relay lists are signed (NIP-65 events signed by DID-derived Nostr key) → relay list substitution requires the identity's private key
- Key Continuity Verification (Mechanism 1) provides Signal-style safety numbers for out-of-band DID verification
- First-contact trust model: TOFU for did:web, self-certifying verification for did:dht

### Layer 2: Group Key Management

**Key decisions:**

- One MLS group per SCP context (1:1 mapping)
- MLS Authentication Service = DID resolution + UCAN validation (no separate trusted server)
- MLS Delivery Service = Nostr relay(s) (explicitly untrusted)
- SDK MUST delete old epoch keys after Commit (forward secrecy enforcement)
- SDK MUST issue periodic MLS Updates (PCS enforcement, recommended every 24 hours)
- KeyPackages (pre-key bundles) published to relays for offline member addition
- DID key rotation triggers MLS Update in all active contexts

### Layer 3: Message Security

**Key decisions:**

- Two independent integrity checks: Ed25519 outer signature (verifiable by anyone) + MLS membership_tag HMAC (verifiable only by group members)
- Three-layer replay prevention: MLS generation numbers + hash-based deduplication + timestamp bounds
- 5-minute clock skew tolerance (generous enough for real devices, tight enough to limit replay windows)
- Per-sender SCP sequence numbers (distinct from MLS generation numbers) for suppression detection
- Merkle log order is authoritative, not timestamps

### Layer 4: Relay Security

**Key decisions:**

- Relay threat model formally defined: can read metadata, drop, delay, replay, equivocate; cannot forge, decrypt, modify, inject
- Relay Consistency Protocol (Mechanism 2): periodic signed Merkle root comparison between members
- Multi-relay strategy: publish to 3+ relays, per-relay reliability scoring
- Suppression detection: sequence gaps + heartbeats
- Selective suppression of MLS Commits doesn't breach confidentiality (MLS epoch ratcheting protects)

### Layer 5: Metadata Privacy

**Key decisions:**

- Honest documentation of what's exposed (sender DID, context ID, timestamps, sizes)
- Cross-context key isolation (separate MLS groups, independent key material)
- Mixnet/cover traffic/PIR explicitly out of scope for v1
- Identity key signs but never directly encrypts group content (limits side-channel impact)

---

## 5. The Five Security Mechanisms

### Mechanism 1: Key Continuity Verification

**Problem:** Even with self-certifying DIDs, how does Alice know the DID she has for Bob is really Bob's and not an attacker's?

**Solution:** Safety number style verification. Compute `SHA256(sort(alice_did, bob_did) || alice_pubkey || bob_pubkey)`. Display as 12-word mnemonic or 60-digit number. Compare out-of-band (in person, voice call).

**Key change detection:** TOFU records key on first encounter. Any change triggers alert + invalidates previous verification. Legitimate changes (rotation, recovery) are distinguishable because the new DID document is signed by the old key (authorization chain).

### Mechanism 2: Relay Consistency Protocol

**Problem:** A malicious relay can show different event histories to different members.

**Solution:** Periodic signed checkpoints containing (context_id, event_count, merkle_root, epoch). Sent as encrypted MLS messages. ANY divergence between ANY two honest members detects equivocation — this is not a majority vote, so Sybil amplification doesn't help.

**Design insight:** The key realization is that equivocation detection doesn't require consensus. If two honest members compare and disagree, equivocation has occurred. Period. The number of Sybil members who "agree" with the attacker is irrelevant.

### Mechanism 3: Message Deduplication

**Problem:** Relays can replay old messages. MLS generation numbers catch exact replays within an epoch, but a relay could replay messages from old epochs if it retained old key material.

**Solution:** Three-layer defense. Hash dedup catches exact replays. Sequence tracking catches ordering violations. Timestamp bounds catch time-shifted replays.

### Mechanism 4: Compromise Recovery Flow

**Problem:** What happens when a key is compromised?

**Solution:** Ordered recovery protocol: key rotation on trusted device → MLS Update in all contexts (PCS) → UCAN revocation → KeyPackage rotation → contact notification → private state re-encryption.

**Key insight:** MLS's post-compromise security means recovery is automatic once the compromised member issues an Update. The vulnerability window is bounded by the PCS Update interval. Shorter intervals = smaller windows.

### Mechanism 5: Ephemeral Key Destruction Verification

**Problem:** How do you verify that ephemeral context keys were actually destroyed?

**Solution:** Platform-attested destruction where available (Secure Enclave attestation that key handle is invalid). Three trust levels: hardware-attested (high), software-only (moderate), no attestation (none).

**Honest limitation:** Proving remote key destruction is impossible in the general case. A compromised device can lie. The protocol provides the strongest guarantees the hardware supports and is explicit about where those guarantees end.

---

## 6. Subtle Attacks Analyzed

### Proposal MITM (relay + compromised DID resolution)

Attack: Relay intercepts proposal + attacker MITM's Bob's DID resolution → attacker decrypts proposal, modifies, re-encrypts to Bob.

Defense: For did:dht, DID resolution MITM is impossible (self-certifying). For did:web, TLS pinning + TOFU limits the window. Key Continuity Verification eliminates the attack post-verification.

### Selective relay suppression (suppress removal events)

Attack: Relay suppresses an MLS Remove Commit, keeping excluded member in the group.

Defense: After the Commit, new messages use the new epoch key. The removed member does NOT have this key — they physically cannot decrypt new messages. Suppressing the Commit from other members causes DoS (they can't advance epochs), not confidentiality breach. Multi-relay delivery of Commits mitigates the DoS.

### Time-shifted key compromise

Attack: Attacker extracts MLS state at time T, waits, acts as victim.

Defense: Forward secrecy protects messages before T (old epoch keys deleted). PCS protects messages after the next Update. The vulnerability window = time between compromise and next Update. Recommended 24-hour Update interval bounds this.

### Sybil-amplified relay equivocation

Attack: Attacker controls relay + Sybil members. Relay shows consistent-but-different history to honest vs. Sybil members.

Defense: Relay Consistency Protocol is not majority-vote. Two honest members comparing checkpoints detect equivocation regardless of Sybil count.

### Cross-context key correlation

Attack: Compromising one context reveals keys for other contexts.

Defense: Each context is a separate MLS group with independent key material. Identity key is shared across contexts but signs (never encrypts group content). Compromising context A's MLS state reveals nothing about context B's MLS state.

---

## 7. Architectural Decisions (Closed)

### Single Ciphersuite for v1
**Decision:** One ciphersuite. No negotiation.
**Rationale:** Negotiation adds complexity and downgrade attack surface. All implementations use the same algorithms. Revisit in v2.

### MLS Authentication Service = DID Verification
**Decision:** No separate trusted AS server. SCP's identity layer IS the AS.
**Rationale:** Adding a centralized AS would undermine SCP's decentralized architecture. DID self-certification (did:dht) provides the trust root without any server.

### Relay Consistency via Checkpoints, Not Consensus
**Decision:** Periodic Merkle root comparison, not distributed consensus (Raft/PBFT).
**Rationale:** Consensus is heavy, requires synchronous communication, and doesn't match SCP's asynchronous relay-based architecture. Checkpoints are lightweight (one message per member per interval) and detect equivocation with just two honest members.

### Honest About What We Can't Enforce
**Decision:** The spec explicitly documents what ephemeral key destruction can and cannot guarantee.
**Rationale:** Claiming full enforcement when the protocol can't reach into device hardware would be dishonest. Better to provide hardware-attested destruction where available and be explicit about the trust levels.

### Timestamp as Hint, Not Authority
**Decision:** Merkle log order is authoritative. Timestamps are for replay bounds and ordering hints.
**Rationale:** Synchronized clocks are unreliable across devices. Making timestamps authoritative would create clock-manipulation attacks. The Merkle log provides a tamper-evident ordering that doesn't depend on clock accuracy.

---

## 8. Open Questions (Reduced to 4)

1. **PCS Update frequency.** Recommended 24 hours, but high-security contexts may want shorter intervals. Should this be a context-level parameter?

2. **KeyPackage buffer size.** Recommended 10 per identity on relays. What's the right number for high-activity identities that join many contexts?

3. **Relay scoring algorithm.** Per-relay reliability scoring is specified as local to each client. Should the protocol recommend a specific scoring formula, or leave it entirely to implementations?

4. **Metadata privacy roadmap.** v1 accepts metadata exposure. When (if ever) should mixnet/cover traffic be added? Is this a v2 feature or perpetually out of scope?

---

## 9. Relationship to Prior Decisions

### MLS Selection (Planning Session 04)
This session specifies HOW MLS integrates with SCP. Planning session 04 chose MLS; this session maps MLS concepts to SCP concepts, specifies SDK requirements for forward secrecy and PCS, and defines the key lifecycle.

### did:dht Selection (Planning Session 04)
did:dht's self-certification property is the foundation of Layer 1. This session makes explicit why did:dht was chosen over did:web for the target method: self-certification eliminates the largest class of MITM attacks.

### Nostr Transport (Planning Session 04)
Nostr's signed events (NIP-65 relay lists) provide relay list authentication. NIP-42 relay authentication is supported but not required. The multi-relay strategy builds on Nostr's existing relay pool architecture.

### Ephemeral Memory Scope (Planning Session 03)
Mechanism 5 (Ephemeral Key Destruction Verification) gives operational specifics to the memory scope concept. "Destroy keys" now has a concrete protocol: MLS group state destruction + platform attestation + signed destruction attestation.

### Encryption-as-Access-Control (Planning Session 02)
Layer 2 (Group Key Management) specifies the cryptographic mechanics behind encryption-as-access-control. The concept was established in session 02; this session provides the MLS-level implementation specification.

---

## 10. What This Session Did Not Cover

- **Specific DID:DHT library evaluation.** The security properties of did:dht are specified; the library choice is unresolved.
- **MLS interoperability testing.** OpenMLS is chosen (planning session 04), but conformance testing with other MLS implementations is future work.
- **Formal security proofs.** MLS has published formal analyses (ETK, TreeSync). SCP's composition of MLS + DID + UCAN + Merkle logs has not been formally analyzed.
- **Quantum resistance.** The selected ciphersuite (X25519, Ed25519) is not quantum-resistant. Post-quantum migration is a future concern, likely addressable by ciphersuite upgrade.
- **Side-channel attacks on mobile devices.** Secure Enclave / Android Keystore provide hardware protection, but timing attacks and power analysis are device-specific concerns outside protocol scope.
