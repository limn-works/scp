# SCP Open Questions — Resolved Decisions

**Date:** February 22, 2026
**Resolved by:** Autonomous agent (Alec unavailable), following design principles from planning-session-06.md
**Rationale:** Each decision follows the protocol's principles: simple over complex, no deferral, no operator dependency, transport independence, encryption-as-access-control. All 10 suggestions from open-questions.md are confirmed — each was thoroughly analyzed with clear tradeoffs and the suggestions are consistent with the protocol's security posture.

---

## Decision 1: Push Notification Opacity

**Decision: Fully opaque. Mandatory.**

Push payloads contain a wake signal and nothing else. No context ID, no sender DID, no message preview, no metadata. The device wakes, connects to relays, pulls encrypted envelopes. Apple/Google learn only that the device received a notification at a specific time.

**Write into:** spec §10.7 as mandatory requirement.

---

## Decision 2: Envelope Format — Minimal Outer Envelope

**Decision: Minimal outer envelope.**

The outer envelope (what relays see) contains only:
1. **Routing identifier** — per-context pseudonym (see Decision 7)
2. **Recipient hint** — recipient pseudonym for directed messages, or broadcast marker
3. **Blob TTL** — how long the relay should store before deletion
4. **Encrypted blob** — everything else

Sender identity, timestamps, sequence numbers, epoch, generation — all inside the encrypted payload. The relay is a dumb pipe that holds encrypted blobs for a specified duration and delivers them to subscribers of a routing ID.

Relay-side ordering, dedup, and expiry are NOT the relay's job. The SDK handles all of this. The relay stores blobs and deletes them when the TTL expires.

**Write into:** spec §9.5 (update signature scope for inner envelope), spec §9.10 (replace §9.10.2 exposed metadata), sketch §11 (redesign wire format).

---

## Decision 3: Message Size Normalization — Fixed Bucket Padding

**Decision: Fixed bucket padding. Buckets: 256B, 1KB, 4KB, 16KB, 64KB, 256KB.**

Pad plaintext to the next bucket boundary before encryption. Recipients strip padding after decryption. Messages larger than 256KB are chunked into 256KB blocks.

Padding happens below the application layer and above the transport layer — the SDK handles it transparently. Application developers never see it. Relay operators see uniform bucket-sized blobs.

**Write into:** spec §9.10 as new subsection (§9.10.6 or renumbered).

---

## Decision 4: A2A Propose/Accept — Remove Entirely

**Decision: Remove.**

Cross-context tool calls with stateful sessions (§6.2) cover all governed inter-agent interaction. Agents that share no context cannot directly reach each other. The human bridges across their own contexts locally. Context isolation is the security boundary working as designed.

**Remove from spec:**
- §5.12 (propose/accept)
- §6.1 A2A isolation paragraph
- §6.3 propose/accept references
- §6.4 (all three subsections — replace with §6.2.2 tool-interface discovery only)
- §9.2 A2A-specific threat vectors (4 items)
- §3.6 A2A activity visibility paragraph

**Remove from sketch:**
- §2 propose/accept/reject/listProposals APIs
- §11 context proposal envelope, introduction token wire format
- §12 registry contexts, referral/introduction APIs
- §14 A2A use cases (entire section)

**Remove from architecture:**
- §2.3 A2A data flow
- §3.2 Discovery Engine references to registries/referrals/introduction tokens
- §5 MVSDK "what's not in" A2A references
- §6 Build phases A2A references

**Keep (valuable independent of A2A):**
- TTL (§5.10)
- Memory scope (§5.11)
- Provenance (§7.7)
- Context-mediated discovery via tool interfaces (§6.2.2)

---

## Decision 5: Sender-Side Key Layer — AES-256 Symmetric, HPKE-Wrapped Distribution

**Decision: Symmetric AES-256 sender keys, HPKE-wrapped per-recipient distribution via MLS, sender-first encryption, protocol-notified mutual block.**

- **Key type:** AES-256 symmetric. One key per sender per context.
- **Distribution:** Via MLS application messages, but each sender key is HPKE-encrypted to individual recipients' X25519 public keys (from their MLS LeafNode). MLS application messages are group-readable, so HPKE wrapping prevents blocked parties from reading the new key. New members receive sender keys from each existing member individually. Key rotation for blocking: HPKE-encrypted payloads for each non-blocked member in a single MLS message.
- **Encryption order:** Sender-first (AES-256-GCM), then MLS. Blocked party can decrypt MLS layer but gets opaque ciphertext from the blocker.
- **Mutual blocking:** Protocol sends block notification (MLS application message: "you have been blocked by DID X"). Dave's client automatically rotates Dave's sender key excluding Alice. Both sides complete within one message round-trip.
- **Block observability:** Block events are observable to the group (the recipient list of HPKE payloads reveals who was excluded). Acceptable tradeoff — cryptographic enforcement is prioritized over concealing block events.
- **Storage:** 32 bytes per sender key per context member. Trivial.
- **Forward secrecy interaction:** Sender keys rotate ONLY on block events, NOT on MLS epoch advances. Old sender keys retained for historical message decryption. Blocking is about future messages, not retroactive access.

**Write into:** spec as new §9.16 (Sender-Side Key Layer).

---

## Decision 6: Connection Privacy — Persistent Connections + TLS

**Decision: Persistent connections where platform allows. TLS 1.3 required. No IP-layer anonymization mandate.**

1. **Persistent connections mandatory on desktop/workstation/server.** Constant connection to each relay regardless of activity. Prevents connection-timing correlation.
2. **Mobile: push-wake + burst.** Opaque push wakes device, SDK connects to relays, exchanges messages, disconnects.
3. **TLS 1.3 required for all relay connections.** Relay operators see client IP addresses — the same information any web server sees. Combined with per-context pseudonyms, relay cannot link IP to identity.
4. **No IP-layer anonymization mandate.** The protocol does not require Tor, VPN, or mix networks. The privacy posture already exceeds any conventional app. Clients with heightened privacy needs can route through Tor or a VPN at the transport layer — this is a client configuration choice, not a protocol requirement.
5. **No custom mix network, no custom proxy protocol.** No new infrastructure required.

**Write into:** spec §9.10 (new subsection on connection privacy).

---

## Decision 7: Per-Context Pseudonyms — Yes, Inside-Encryption Verification

**Decision: Implement per-context pseudonyms. Inside-encryption verification.**

Each participant derives a per-context keypair:
```
context_seed = HKDF(identity_private_key, context_id, "scp-context-pseudonym")
context_keypair = Ed25519_keygen(context_seed)
context_pseudonym = context_keypair.public_key
```

- Deterministic: same identity + same context = same pseudonym
- Unlinkable across contexts: different context_id = different pseudonym
- Verification: sender includes DID inside MLS-encrypted payload. Group members verify pseudonym-to-DID mapping on first encounter and cache.
- No ZK proofs — unnecessary complexity since only group members need verification.
- Pseudonym replaces sender DID in outer envelope. Full DID inside encrypted payload.
- SDK handles derivation, caching, and verification transparently.

**Write into:** spec §9.10 (new subsection), update §10.5 envelope format.

---

## Decision 8: Cover Traffic — Configurable, Default On

**Decision: Constant-rate cover traffic on persistent connections, enabled by default, configurable per-client. Not applicable on push-wake connections.**

1. **Persistent connections: constant-rate, default on.** One padded message per relay connection per 30 seconds. Real messages replace dummy messages. ~15MB/day for 5 relay connections at 1KB padding. Clients or operators may disable via SDK configuration; disabling degrades traffic analysis resistance but has no functional impact.
2. **Push-wake connections: no cover traffic.** Connection is transient and brief.
3. **Dummy message format:** Single-byte flag inside encrypted payload distinguishes real from dummy. Recipients decrypt, check flag, discard dummies.
4. **Rate is per relay connection, not per context.** Prevents relay from correlating traffic rate changes with context activity.

**Write into:** spec §9.10 (new subsection on traffic analysis defense).

---

## Decision 9: DID Resolution Privacy — Local DHT Node + Caching

**Decision: Local DHT node on persistent devices. Lightweight resolution on mobile. Aggressive caching.**

1. **Desktop/workstation/server: local Mainline DHT node, mandatory.** DID resolution queries become indistinguishable from DHT routing traffic.
2. **Mobile: DHT queries via standard HTTPS gateway or lightweight DHT client.** Resolution is infrequent (once per first contact, then cached), so latency is acceptable.
3. **Aggressive caching:** 24-hour refresh for active contacts, 7-day for inactive. Stale documents detected via BEP44 sequence number comparison. Key change alerts trigger immediate re-resolution.
4. **No batch/prefetch, no resolution proxy.** Local DHT node on desktop and caching on mobile provide practical privacy without new infrastructure.

**Write into:** spec §9.10 (new subsection on resolution privacy).

---

## Decision 10: Relay Query Privacy — Pseudonyms + Partitioning

**Decision: Per-context pseudonyms + mandatory relay set partitioning. No subscription mixing (removed — decoy routing IDs receive zero traffic, making them trivially distinguishable from real subscriptions). No PIR.**

1. **Per-context pseudonyms (from Decision 7) are the foundation.** Relay can't link subscriptions across contexts.
2. **Relay set partitioning, mandatory.** Each context SHOULD use different relays from the client's other contexts. SDK distributes contexts across relays to minimize overlap.

**Combined effect:** Relay sees pseudonyms (unlinkable to identity) on a relay hosting only a fraction of the client's total context set.

**Write into:** spec §9.10.8.

---

## Summary

All 10 questions resolved. All suggestions confirmed. The decisions collectively form a coherent metadata privacy architecture layered on top of the existing cryptographic security model:

- **Envelope layer:** Minimal outer envelope with pseudonyms (#2, #7)
- **Content layer:** Fixed bucket padding (#3)
- **Connection layer:** Persistent connections + TLS (#6)
- **Traffic layer:** Constant-rate cover traffic (#8)
- **Resolution layer:** Local DHT + caching (#9)
- **Query layer:** Pseudonyms + partitioning (#10)
- **Push layer:** Fully opaque (#1)
- **Blocking layer:** AES-256 sender-side keys (#5)
- **Interaction layer:** No A2A — tool interfaces only (#4)
