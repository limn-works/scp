# SCP Open Questions

**Date:** February 22, 2026
**Context:** Design review of PR #1 (architecture branch). These questions emerged from reviewing the architecture document, planning sessions 03–05, and the spec/sketch updates. Each requires a decision before implementation.

**Ordering:** Simplest to most complex.

---

## 1. Push Notification Opacity

**Question:** Should push notification payloads (APNs/FCM) be mandated as fully opaque?

**Background:** Push notifications go through Apple (APNs) and Google (FCM) infrastructure. Whatever is in the payload, Apple and Google can read. The current spec mentions opaque payloads but doesn't mandate it.

**Options:**

**A. Fully opaque (recommended).** Push payload contains only a wake signal — "you have messages." No context ID, no sender DID, no message preview, no metadata. The device wakes, connects to relays over TLS, and pulls encrypted envelopes. Apple/Google learn only that the device received a notification at a specific time.

**B. Minimal metadata.** Push payload includes a context ID or message count so the app can prioritize which relays to check first. Apple/Google learn which contexts are active and when.

**Tradeoffs:**

| | Fully opaque | Minimal metadata |
|---|---|---|
| Privacy | Apple/Google learn nothing beyond "notification received" | Apple/Google learn context activity patterns |
| Latency | App must check all relays on wake — slightly slower | App can check the relevant relay first — slightly faster |
| Complexity | Simple — one payload format | Requires per-context routing logic in push |
| Battery | May wake more frequently if checking all relays | More targeted wakes |

**Analysis:** The latency and battery differences are marginal. The privacy difference is not. Apple and Google already have enormous surveillance capability via device telemetry — SCP should not voluntarily add to it. Fully opaque push is the only option consistent with the protocol's privacy posture.

**Suggestion: Fully opaque. Mandate it.**

Push payloads contain a wake signal and nothing else. The device wakes, connects to relays, pulls envelopes. The marginal latency cost of checking multiple relays on wake is irrelevant compared to voluntarily handing Apple and Google a real-time activity feed. This is not a tradeoff — it's the only option that doesn't contradict the protocol's reason for existing. Write into spec as a mandatory requirement.

---

## 2. Envelope Format Metadata Opacity

**Question:** How much metadata should be visible in the outer SCP envelope (the part relays can read) versus encrypted inside the payload?

**Background:** Currently the spec describes envelopes with plaintext context_id, sender DID, timestamp, epoch, generation number, and sequence number in the outer layer. Relays see all of this. The encrypted payload is inside.

**Options:**

**A. Minimal outer envelope.** The outer envelope contains only what the relay needs for routing:
- A routing identifier (could be context_id, or a per-context pseudonym — see question #7)
- The encrypted blob
- A delivery hint (recipient pseudonym or broadcast)

Everything else — sender DID, timestamp, sequence number, epoch, generation number — goes inside the encrypted payload. Relays learn: which routing ID, blob size, when they received it. Nothing else.

**B. Current design (more metadata outside).** Sender DID, context_id, timestamp, epoch, generation, and sequence are all in the outer envelope. Relays learn: who sent what to which context, when, and the message ordering.

**C. Hybrid.** Context_id and sender pseudonym (not DID — see question #7) in the outer envelope for routing. Timestamp in outer for relay-side ordering and expiry. Everything else inside.

**Tradeoffs:**

| | Minimal outer | Current design | Hybrid |
|---|---|---|---|
| Relay metadata exposure | Routing ID + blob size only | Full sender/context/timing | Pseudonym + timing |
| Relay-side ordering | Not possible (relay stores blobs) | Relay can order by timestamp | Relay can order by timestamp |
| Relay-side dedup | Not possible (relay stores blobs) | Relay can dedup by signature hash | Limited |
| Relay-side expiry | Client must clean up | Relay can expire by timestamp | Relay can expire by timestamp |
| Complexity | Higher — client does more work | Lower — relay does more | Medium |

**Analysis:** The tension is between relay functionality and metadata privacy. Relays that can't read timestamps can't expire old messages, can't order delivery, and can't deduplicate. But relay-side ordering and dedup are convenience features, not security requirements — the SDK handles all of this client-side anyway (§9.8). Relay-side expiry matters for storage management, but can be handled by blob TTL (relay stores blob for N hours, then deletes, regardless of content).

Moving sender DID inside encryption is the highest-value change — it prevents relays from building social graphs of who talks in which context. Timestamps are lower-value since the relay knows when it received the blob anyway.

**Suggestion: Minimal outer envelope (Option A).**

The relay is untrusted infrastructure. Give it the minimum it needs to do its job — route a blob to a destination — and nothing else. The outer envelope contains:

1. A routing identifier (context pseudonym — see #7)
2. A recipient hint (recipient pseudonym for directed messages, or broadcast marker)
3. A blob TTL (how long the relay should store it before deletion — enables relay-side storage management without timestamps)
4. The encrypted blob

That's it. Sender identity, timestamps, sequence numbers, epoch, generation — all inside the encrypted payload. The relay is a dumb pipe that holds encrypted blobs for a specified duration and delivers them to subscribers of a routing ID.

Relay-side ordering, dedup, and expiry are not the relay's job. The SDK handles all of this (§9.8). The relay stores blobs and deletes them when the TTL expires. This is simpler for relay implementers (the SCP native relay becomes trivially simple), stronger for privacy, and consistent with the protocol's posture that relays are untrusted.

The blob TTL replaces relay-side timestamps for storage management. The client sets it. The relay doesn't need to know when the message was created — only how long to hold it.

---

## 3. Message Size Normalization

**Question:** Should the protocol pad messages to fixed size buckets to prevent size-based traffic analysis?

**Background:** Without padding, message sizes leak information. A relay can distinguish "sent a short text" from "sent a large file" from "sent a tool invocation with structured data." Over time, size patterns can fingerprint activity types.

**Options:**

**A. Fixed bucket padding.** All messages are padded to the next size bucket before encryption. Proposed buckets: 256B, 1KB, 4KB, 16KB, 64KB, 256KB. Messages larger than 256KB are chunked into 256KB blocks. Recipients strip padding after decryption.

**B. Random padding.** Each message is padded with a random number of bytes (up to some maximum). Cheaper than fixed buckets but provides weaker guarantees — statistical analysis over many messages can still estimate true size.

**C. No padding.** Accept the size leak. Focus privacy efforts elsewhere.

**Tradeoffs:**

| | Fixed buckets | Random padding | No padding |
|---|---|---|---|
| Privacy | Strong — observer sees bucket sizes only | Moderate — statistical inference possible | None — exact sizes visible |
| Bandwidth overhead | Average ~50% (half each bucket wasted) | Configurable | Zero |
| Complexity | Low — pad to next boundary | Low — append random bytes | None |
| Storage impact | ~50% more relay storage | Variable | None |

**Analysis:** Fixed bucket padding is simple, effective, and the overhead is acceptable. The bandwidth and storage cost is real but manageable — SCP messages are primarily text and structured data, not large media. Media (images, video) will be large regardless and fall into the largest bucket(s), so the relative overhead decreases for large payloads.

The bucket boundaries should be chosen so that the most common message sizes (short text: 100-500B, structured tool call: 500B-2KB, longer message: 2-8KB) land in different buckets. The proposed 256B/1KB/4KB/16KB/64KB/256KB progression achieves this.

**Suggestion: Fixed bucket padding (Option A). Buckets: 256B, 1KB, 4KB, 16KB, 64KB, 256KB.**

Simple, deterministic, no statistical leakage. Pad plaintext to the next bucket boundary before encryption. Recipients strip padding after decryption. Messages larger than 256KB are chunked into 256KB blocks (chunk count itself leaks approximate size, but this is acceptable for large payloads which are inherently size-variable).

The ~50% average overhead is real but the right tradeoff. SCP messages are text and structured data — the absolute byte cost is small. A 200-byte text message padded to 256B costs 56 extra bytes. A 3KB tool call padded to 4KB costs 1KB. This is noise compared to the privacy gain.

The padding happens below the application layer and above the transport layer — the SDK handles it transparently. Application developers never see it. Relay operators see uniform bucket-sized blobs.

---

## 4. A2A Propose/Accept — Keep, Modify, or Remove

**Question:** Does the protocol need agent-to-agent context proposals (§5.12), or do cross-context tool calls with stateful sessions (§6.2) cover all inter-agent interaction needs?

**Background:** The PR introduced propose/accept as a way for agents to create bilateral contexts for multi-turn negotiation. During review, we identified that cross-context tool calls — now updated with explicit context governance and stateful session support (§6.2.1) — cover the same use cases with stronger governance. The remaining unique capability of propose/accept is reaching agents that share no context (strangers).

**The core tension:** Agent isolation (§6.1) exists to prevent cross-context information flow and the attack vectors that come with it. Propose/accept creates a governed channel for exactly that. Is governed cross-boundary communication an improvement over no cross-boundary communication, or does it reintroduce the risks isolation was designed to eliminate?

**Options:**

**A. Remove entirely.** Cross-context tool calls handle all structured inter-agent interaction. Agents that share no context cannot directly reach each other. The human bridges across their own contexts locally. If you want to interact with an agent, join a context they're in (or have the human arrange it). Sections §5.12, §6.4, and all A2A-specific content in §9 are removed.

Implications of removal:
- No agent-to-agent "cold outreach." Agents can only interact through shared contexts.
- Discovery (§6.4) becomes simpler — context-mediated discovery via tool interfaces (§6.2.2) is the only mechanism. No registries, no referral chains.
- The Moltbook argument ("agents will communicate outside the protocol") stands, but the response is: let them. SCP's value is that interactions inside the protocol are trustworthy. Interactions outside are not. Clean boundary.
- Simpler protocol. Smaller attack surface. Fewer spec sections. Faster to implement.
- Agents that need to form new relationships require human facilitation — the human joins a context, their agent discovers co-members through tool interfaces, and the human introduces agents by adding them to shared contexts.

**B. Keep but restrict to context-mediated only.** Agents can propose contexts to co-members of contexts they already share. No registry discovery. No referral chains. No reaching strangers. Proposals carry the shared context as provenance. The trust relationship already exists — the proposal is just a way to create a focused sub-interaction.

Implications of context-mediated restriction:
- Preserves bilateral initiation between agents that already have a trust relationship.
- Eliminates the stranger-contact attack surface.
- Registries (§6.4.2) and referrals (§6.4.3) are removed. Only context-mediated discovery (§6.4.1) remains.
- Still creates a new context per interaction, but both parties are already in a shared context — so the trust evaluation is well-grounded.
- Proposal spam is bounded — you can only propose to people you share a context with, and context membership is already governed.

**C. Keep as designed in the PR.** Full propose/accept with registries, referrals, and stranger-contact. The governance mechanisms (earned capacity, trust evaluation, discovery provenance, behavioral record consequences) mitigate the attack surface.

Implications of keeping:
- Agents can reach strangers. This enables agent marketplaces, specialist discovery, cross-network collaboration.
- Full attack surface: proposal spam, agent brigading, Sybil flooding of proposals, discovery manipulation.
- Larger spec. More to implement. More to secure.
- The Moltbook argument is addressed directly — governed A2A within the protocol rather than ungoverned A2A outside it.

**Analysis of the "Moltbook argument":**

The PR argues that without governed A2A, agents will use ungoverned channels (Moltbook, raw HTTP, etc.), so SCP should provide the governed alternative. This argument has two weaknesses:

1. **SCP can't prevent ungoverned communication anyway.** An agent's local orchestration (above the protocol boundary) can make HTTP calls, use Moltbook, or communicate through any channel. Adding governed A2A to SCP doesn't prevent ungoverned A2A — it just provides an alternative. If the alternative is good enough, agents may prefer it. If it's not (too many restrictions), they won't.

2. **The governed alternative reintroduces the risk.** The whole point of isolation was preventing cross-context information flow. Governed A2A says "we'll allow it but with guardrails." But the guardrails (trust evaluation, provenance, earned capacity) are mitigations, not prevention. A sophisticated attacker who builds behavioral history and operates within rate limits can still use A2A for brigading. The guardrails slow the attack; they don't eliminate it.

**Analysis of "tool calls are sufficient":**

The updated §6.2 with stateful sessions covers:
- Multi-turn negotiation (session IDs)
- Structured data exchange (defined schemas)
- Discovery (tool interfaces for member search)
- Context governance on every interaction (both contexts mediate)

What tool calls don't cover:
- Reaching agents you share no context with
- Symmetric peer interaction (tool calls have caller/tool asymmetry)
- Creating a shared space with its own event log for a bilateral interaction

The first gap (reaching strangers) is the main argument for A2A. The second and third are convenience, not necessity.

**Suggestion: Remove entirely (Option A).**

The protocol's core value proposition is governed, trustworthy interaction. Context isolation is the mechanism that delivers it. Propose/accept weakens isolation by creating agent-governed channels that bypass context governance — even with guardrails, the channel exists and can be exploited.

Cross-context tool calls with stateful sessions (§6.2) cover every legitimate inter-agent interaction use case where both parties share a context. The "reaching strangers" gap is not a gap — it's the security boundary working as designed. If you want to interact with someone, you need to share a context. Contexts are how trust is established. Skipping that step is exactly the problem Moltbook demonstrated.

The Moltbook argument ("agents will go around the protocol") is true but irrelevant. SCP doesn't need to compete with ungoverned communication channels. SCP's value is that interactions inside the protocol are trustworthy, verifiable, and accountable. Interactions outside are not. That's a clean, defensible boundary. Blurring it to capture "some" of the ungoverned traffic doesn't make the protocol stronger — it makes the boundary meaningless.

Removing A2A also removes: §5.12 (propose/accept), §6.4 (discovery — replaced by §6.2.2 tool-interface discovery), all A2A-specific threat analysis in §9, context proposals in sketch.md, registry contexts as a concept, referral/introduction tokens, and discovery provenance as a separate type. The protocol becomes smaller, simpler, and harder to attack.

Agents that need to form new relationships do it the same way humans do: through shared contexts. A human joins a context, discovers co-members via tool interfaces, and facilitates introductions by adding agents to shared contexts. The human is the bridge. This is the original design and it was right.

---

## 5. Sender-Side Key Layer Design

**Question:** How exactly does the sender-side key layer for blocking work alongside MLS group encryption?

**Background:** We agreed that blocking is unilateral/per-relationship and uses a sender-side key mechanism separate from MLS group membership. The spec now says messages are "double-encrypted — first with the sender's personal key, then with the MLS group key." This section needs detailed specification.

**Design questions:**

**A. Key type and generation.** What key type for sender-side keys? Options:
- Symmetric (AES-256): Simple. Each sender generates a random symmetric key. Distributes it to all members. Cheap to encrypt/decrypt. Revocation = generate new key, redistribute to everyone except blocked party.
- Asymmetric (X25519 + HPKE): More complex. Each sender generates a keypair. Distributes public key. Messages encrypted to recipients' public keys. Revocation = generate new keypair, distribute new public key to everyone except blocked party. Overkill for this use case since MLS already provides asymmetric group encryption.

**B. Key distribution.** How are sender-side keys distributed?
- Via MLS application messages: The sender's key is encrypted with the MLS group key and sent as a regular context message. All group members can decrypt it and store it. When the sender rotates their key (for blocking), the new key is sent as another MLS application message but encrypted individually to each non-blocked member.
- Via MLS Welcome extensions: New members receive sender-side keys as part of their Welcome message when joining the group. This ensures new members can decrypt existing senders' messages from their join point forward.

**C. Encryption order.** "First sender key, then MLS" or "first MLS, then sender key"?
- Sender-first, then MLS: The sender encrypts their plaintext with their personal key, then MLS encrypts the result. All group members can decrypt the MLS layer (getting the sender-key-encrypted ciphertext). Only members who have the sender's personal key can decrypt the inner layer. This is the correct order — it means the blocked party sees that a message exists from the sender (via MLS) but can't read it (missing sender key).
- MLS-first, then sender: Doesn't make sense — the sender key layer wouldn't be group-aware.

**D. Mutual blocking.** When Alice blocks Dave, Alice rotates her sender key excluding Dave. Does Dave also need to rotate his sender key excluding Alice? Blocking is defined as bidirectional (§3.6: "neither can see the other"). So yes — both parties rotate their sender keys. But Dave doesn't know he's been blocked until Alice's new messages become undecryptable to him (he has the MLS layer but not the new sender key). At that point, Dave's client detects the block and rotates Dave's sender key excluding Alice.

Alternatively: Alice's block action triggers a protocol-level notification to Dave that a block has occurred (without revealing the reason). Dave's client then rotates Dave's sender key excluding Alice. This is cleaner but reveals the block event.

**E. Performance implications.** Double encryption adds computational cost per message. For sender-side symmetric keys (AES-256), this is negligible — AES is hardware-accelerated on all modern devices. The overhead is one AES operation per message on send, and one on receive. Acceptable.

**F. Key storage.** Each member stores one sender key per other member in the context. For a 100-person context, that's 99 symmetric keys (99 * 32 bytes = ~3KB). Trivial.

**Suggestion: Symmetric (AES-256) sender keys, MLS-distributed, sender-first encryption, protocol-notified mutual block.**

Specifics:

- **Key type:** AES-256 symmetric. One key per sender per context. Simple, hardware-accelerated, negligible overhead. Asymmetric is unnecessary — MLS already provides the asymmetric layer.

- **Distribution:** Sender keys are distributed as MLS application messages (encrypted to the group). New members receive all current sender keys via a key-bundle application message sent on join. When a sender rotates their key (for blocking), the new key is sent as individual MLS application messages to each non-blocked member — NOT broadcast to the group, because the blocked party could still decrypt the MLS layer and see who received the new key.

- **Encryption order:** Sender-first, then MLS. The sender encrypts plaintext with their AES-256 sender key, then MLS encrypts the result. All group members decrypt the MLS layer. Only members holding the sender's current key decrypt the inner layer. The blocked party sees an MLS message from the sender but gets opaque ciphertext inside — they know the sender sent something but can't read it.

- **Mutual blocking:** When Alice blocks Dave, the protocol sends Dave a block notification (an MLS application message flagged as a block event — no reason given, just "you have been blocked by DID X"). Dave's client automatically rotates Dave's sender key excluding Alice. Both sides complete within one message round-trip. This is cleaner than having Dave's client detect the block passively (which requires waiting for an undecryptable message), and the block event itself is not sensitive — Dave knows he's been blocked, which is honest.

- **Storage:** 32 bytes per sender key × number of context members. For a 1000-person context: ~32KB. Trivial.

- **Forward secrecy interaction:** Sender keys rotate on block events. They do NOT rotate on MLS epoch advances (that would defeat the purpose — the sender key layer is orthogonal to MLS epochs). Old sender keys can be retained for decrypting historical messages (unlike MLS epoch keys, which are deleted for forward secrecy). This is intentional — blocking is about future messages, not retroactive access.

Write into spec as §9.16 (Sender-Side Key Layer).

---

## 6. Connection Metadata and Relay Topology

**Question:** Should the protocol mandate privacy protections on the network connection layer (between client and relay)?

**Background:** Even with encrypted envelopes and minimal outer metadata, the network connection itself leaks information. The relay sees the client's IP address, TLS fingerprint, connection timing, connection duration, and which WebSocket subscriptions the client holds. Over time, this allows the relay to build a profile of the client's behavior.

**Options:**

**A. Persistent connections (simplest mitigation).** Clients maintain a constant WebSocket connection to each relay regardless of activity. This prevents connection-timing correlation ("Alice connected to relay R at 3pm, message appeared in context X at 3:01pm"). The connection is always on, so the relay can't infer when Alice is actively communicating vs. idle.

Cost: Battery and bandwidth for maintaining idle connections. On mobile, this conflicts with OS power management (iOS/Android aggressively kill background connections). Push notifications partially solve this — the device connects on wake, sends/receives, then disconnects.

**B. Single-hop proxy.** Client → proxy → relay. The proxy sees the client's IP but not the message content (TLS to relay). The relay sees the proxy's IP but not the client's IP. This hides the client's identity from the relay.

The proxy is a new infrastructure component. Who runs it? Users can self-host. Community-operated proxies can exist. The protocol specifies the proxy interface. Multiple proxies can be chained for defense-in-depth.

Cost: Additional latency (one extra hop). Proxy infrastructure needs to exist. Proxy operators become a metadata target (they see client IPs + relay destinations).

**C. Multi-hop mix routing.** Client → mix₁ → mix₂ → mix₃ → relay. Each hop strips one layer of encryption and adds delay. Messages from different clients are mixed at each node, making traffic analysis across the full path difficult.

Cost: Significant latency (each hop adds delay + mixing delay). Mix network infrastructure needs to exist with sufficient traffic volume for effective mixing. Complex to implement. Active research area.

**D. Tor integration.** Client connects to relay via Tor hidden service. The relay runs as a .onion service. Client IP is hidden by Tor's three-hop onion routing. No SCP-specific infrastructure needed — uses existing Tor network.

Cost: Tor adds 2-5 seconds of latency per connection. Tor is blocked in some countries. Mobile Tor clients exist but are battery-heavy. Some relays may refuse Tor connections.

**E. No connection privacy (accept the leak).** The protocol specifies TLS for encryption in transit but doesn't address connection metadata. Accept that relays see client IPs and connection patterns. Focus privacy efforts on envelope-level protections (questions #2, #3, #7, #8).

**Analysis:**

The options form a spectrum from simple (persistent connections) to strong (Tor/mixnet). The question is where on this spectrum to target for v1.

Persistent connections (A) are cheap and effective for timing correlation but don't hide client IP. Single-hop proxy (B) hides client IP but adds infrastructure. Tor (D) provides the strongest guarantee with existing infrastructure but at significant latency cost.

A layered approach is possible:
- Mandate persistent connections where feasible (desktop, agent workstations)
- Spec the proxy protocol so it's available for clients that want IP privacy
- Spec Tor hidden service relay support for high-security deployments
- Make connection privacy configurable per client/per context, with the protocol supporting all options

**Suggestion: Tor hidden service support for relays + persistent connections where platform allows. No custom proxy infrastructure.**

The insight is that Tor already exists, already works, and already solves IP privacy without SCP building custom proxy infrastructure. Custom proxies are new infrastructure that someone has to run — and proxy operators become metadata aggregation points that are potentially worse than the relays they're protecting against. Tor has a large anonymity set, years of battle-testing, and existing client libraries for every platform.

The approach:

1. **SCP native relays MUST support Tor hidden service exposure.** Running a relay as a .onion service is a configuration flag, not a protocol change. The relay implementation includes this.

2. **The SDK MUST support connecting to relays via Tor.** Tor client libraries exist for all target platforms (arti for Rust, Tor.framework for iOS, OrbotKit for Android). The transport abstraction treats Tor-connected relays identically to direct-connected relays — the privacy layer is below the transport interface.

3. **Persistent connections are mandatory on platforms that support them** (desktop, agent workstations, servers). The client maintains a constant connection to each relay regardless of activity. This prevents connection-timing correlation.

4. **Mobile clients use push-wake + Tor-connected burst.** The phone is dormant. Push wakes it (opaque push — see #1). The SDK connects to relays via Tor, pulls envelopes, sends pending messages, disconnects. The relay sees a Tor exit node connecting briefly. It can't correlate this to an identity. The burst pattern is inherently different from persistent connections, but Tor hides which device is behind it.

5. **No custom mix network, no custom proxy protocol.** These are new infrastructure that contradicts the principle that the protocol requires no operator. Tor is existing infrastructure that anyone can use. If Tor is insufficient for a specific deployment, the transport abstraction supports plugging in alternative privacy layers — but the protocol doesn't spec custom infrastructure.

This gives strong connection privacy (IP hidden from relay, timing hidden on persistent connections) with zero new infrastructure. The cost is Tor latency on mobile (2-5 seconds per connection burst) and the dependency on Tor client libraries. Both are acceptable.

---

## 7. Per-Context Pseudonymous Identifiers

**Question:** Should the protocol use per-context pseudonyms instead of DIDs in the outer envelope, so relays can't correlate a user's activity across contexts?

**Background:** Currently, the sender's DID appears in the outer envelope. A relay serving multiple contexts can see that DID X participates in contexts A, B, and C, and correlate activity timing across all three. Per-context pseudonyms would replace the DID with a context-specific identifier that the relay can't link back to the DID or to pseudonyms in other contexts.

**Mechanism:**

Each participant derives a per-context keypair from their identity key:

```
context_seed = HKDF(identity_private_key, context_id, "scp-context-pseudonym")
context_keypair = Ed25519_keygen(context_seed)
context_pseudonym = context_keypair.public_key
```

The pseudonym is deterministic (same identity + same context = same pseudonym) but unlinkable across contexts (different context_id = different pseudonym). The relay sees consistent pseudonyms within a context but can't link them across contexts or back to the DID.

**The verification problem:** Counterparties need to verify that the pseudonym belongs to a valid DID — otherwise anyone could generate arbitrary pseudonyms. Options:

**A. Zero-knowledge proof.** The sender attaches a ZK proof that their pseudonym derives from a valid DID without revealing which DID. Counterparties verify the proof. This provides the strongest privacy but requires ZK infrastructure (proof generation, verification circuits).

Feasibility: Ed25519 key derivation proofs are possible with existing ZK systems (Bulletproofs, Groth16, Plonk). Proof generation adds ~50-200ms per message on modern hardware. Proof size is ~1-2KB. This is feasible but adds meaningful complexity to the protocol.

**B. Inside-encryption verification.** The sender includes their DID inside the MLS-encrypted payload. Counterparties (who can decrypt) verify the pseudonym-to-DID mapping. The relay (which can't decrypt) only sees the pseudonym. This is simpler than ZK but means the privacy guarantee is "relays can't link, but group members can."

Feasibility: Trivial to implement. No new cryptographic primitives. The pseudonym-to-DID mapping is verified by each group member on first encounter and cached.

**C. Pseudonym registry per context.** The context maintains a mapping of pseudonym → DID, encrypted to the MLS group key. New members receive the mapping as part of their Welcome message. The relay never sees the mapping.

Feasibility: Simple. Adds a small amount of MLS-encrypted state per context. The mapping is updated when members join/leave.

**Tradeoffs:**

| | ZK proofs | Inside-encryption | Pseudonym registry |
|---|---|---|---|
| Relay unlinkability | Yes | Yes | Yes |
| Non-member verification | Yes (anyone can verify) | No (only group members) | No (only group members) |
| Complexity | High (ZK circuits) | Low | Low |
| Performance | ~50-200ms proof gen per message | None | None |
| Proof size overhead | ~1-2KB per message | None | None |

**Analysis:** Inside-encryption verification (B) provides relay unlinkability with minimal complexity. The relay can't link pseudonyms across contexts, which is the primary goal. The fact that group members can link pseudonyms to DIDs is not a privacy concern — they already know each other's DIDs through MLS membership.

ZK proofs (A) add value only if non-members need to verify pseudonyms — e.g., for relay-side accountability or cross-context verification without decryption. This is a niche use case for v1.

The pseudonym registry (C) is functionally equivalent to inside-encryption verification but adds explicit state management. Inside-encryption is simpler.

**Suggestion: Yes, implement per-context pseudonyms. Use inside-encryption verification (Option B).**

Per-context pseudonyms are the single highest-value metadata privacy mechanism in this list. Without them, a relay that hosts multiple contexts can trivially build a social graph: "DID X participates in contexts A, B, and C; DID X and DID Y are both in context B; DID X was active in A at 3pm and B at 3:05pm." With pseudonyms, the relay sees unrelated identifiers in each context and can't link them.

Inside-encryption verification is the right mechanism because:

- It achieves the goal (relay unlinkability) with zero cryptographic overhead per message. No ZK proofs, no additional computation on the hot path.
- Group members can verify pseudonym-to-DID mappings by decrypting the payload, which they're already doing. The mapping is verified once on first encounter and cached.
- The privacy boundary (relay can't link, members can) is the correct boundary. Members already know each other through MLS — hiding DIDs from them would be absurd.
- ZK proofs solve a problem that doesn't exist in this protocol. Non-members never need to verify pseudonyms — they can't decrypt the messages anyway. The only use case for non-member pseudonym verification would be relay-side accountability, but the relay is untrusted infrastructure and shouldn't be doing verification at all.

The derivation is deterministic (HKDF from identity key + context_id), so the same identity always produces the same pseudonym for a given context — consistent within-context identity without cross-context linkability.

Implementation: the pseudonym replaces the sender DID in the outer envelope. The full DID is inside the encrypted payload. The SDK handles derivation, caching, and verification transparently. Application developers never see pseudonyms.

This pairs with the minimal outer envelope (#2) — the outer envelope contains the context routing ID, the sender's context pseudonym, the blob TTL, and the encrypted blob. That's everything the relay needs and nothing more.

---

## 8. Cover Traffic

**Question:** Should the protocol mandate dummy messages to obscure real activity patterns?

**Background:** Without cover traffic, message timing and frequency reveal activity patterns. A relay can determine: when a user is active, how often they communicate in each context, activity bursts (indicating meetings, events, or heated discussions), and quiet periods (sleep, offline, inactive contexts). Over time, this builds a behavioral profile.

**Mechanism:**

Cover traffic consists of dummy encrypted envelopes that are indistinguishable from real messages. They use valid encryption (the relay can't tell they're dummy), valid pseudonyms, and valid routing — but the content, when decrypted by group members, is a flag indicating "discard." Recipients silently drop dummy messages.

**Options:**

**A. Mandatory constant-rate cover traffic.** Every active relay connection produces messages at a constant rate (e.g., 1 message per 30 seconds). Real messages replace dummy messages in the stream. The relay sees a constant flow regardless of actual activity.

Cost: Bandwidth = (number of relay connections) × (message rate) × (padded message size). For 5 relay connections at 1 msg/30s with 1KB padding = 5 × 2/min × 1KB = 10KB/min = ~15MB/day. Meaningful on mobile data.

Privacy: Strong. The relay sees constant-rate traffic and can't distinguish active periods from idle periods.

**B. Poisson-distributed cover traffic.** Dummy messages are sent at random intervals following a Poisson distribution (mean rate configurable). Real messages are sent normally on top of the cover traffic. The relay sees variable-rate traffic but can't easily distinguish real messages from dummy ones.

Cost: Lower than constant-rate because the mean rate can be set lower. Configurable per client.

Privacy: Moderate. Statistical analysis over long periods can estimate the ratio of real to dummy messages, especially if real message patterns differ from the Poisson distribution. Better than nothing, weaker than constant-rate.

**C. Activity-triggered cover traffic.** Cover traffic only flows when the context is "active" (recent real messages). This avoids the cost of covering inactive contexts but reveals which contexts are active vs. dormant.

Cost: Lower — no traffic for inactive contexts.

Privacy: Weak for activity/inactivity detection. Moderate within active periods.

**D. No cover traffic.** Accept the timing leak. Focus privacy efforts on other layers.

**Analysis:**

Cover traffic's effectiveness depends on volume. A single user generating cover traffic is trivially distinguishable from a network of users all generating cover traffic. The privacy guarantee improves as more participants use the same relay with cover traffic enabled — the relay sees a mix of real and dummy messages from many users and can't attribute timing to any individual.

For v1, the practical question is: what's the mobile bandwidth/battery budget? Constant-rate (A) at 15MB/day is acceptable for WiFi-connected agent workstations but problematic for phones on cellular data. Poisson (B) is more practical for mobile.

A hybrid approach: agent workstations and desktop clients use constant-rate. Mobile clients use Poisson with a lower mean rate. The protocol specifies the dummy message format and leaves the traffic profile as a client configuration.

**Suggestion: Mandatory cover traffic on persistent connections. Not applicable on push-wake connections.**

The key realization: cover traffic and connection model are linked. On persistent connections (desktop, workstation), cover traffic is cheap and effective — you're already maintaining the connection, adding dummy messages is marginal cost. On push-wake connections (mobile), cover traffic is both expensive (battery, cellular data) and ineffective — the connection is inherently bursty (wake, exchange, disconnect), so the relay already knows you're active during the burst and idle otherwise. Cover traffic during a burst doesn't hide the burst itself.

The approach:

1. **Persistent connections: constant-rate cover traffic, mandatory.** One padded message per relay connection per 30 seconds. Real messages replace dummy messages in the stream. The relay sees a constant flow at a predictable rate. It can't distinguish active periods from idle periods. Bandwidth: ~15MB/day for 5 relay connections at 1KB padding. Acceptable for always-on devices.

2. **Push-wake connections: no cover traffic.** The connection is transient. The relay knows the device connected, exchanged messages, and disconnected. Cover traffic during the burst doesn't hide the burst. Tor (see #6) hides which device is behind the burst, which is the more important privacy property for mobile.

3. **Dummy message format:** Inside the encrypted payload, a single-byte flag distinguishes real messages from dummy messages. Recipients decrypt, check the flag, and silently discard dummies. The flag is inside encryption — the relay can't distinguish real from dummy. Dummy messages use the same padding buckets (#3) as real messages.

4. **Cover traffic rate is not configurable per context.** It's per relay connection. This prevents the relay from correlating traffic rate changes with context activity. One rate, all the time, on every persistent connection.

This is simple, low-overhead for the devices that use it, and doesn't apply where it wouldn't help. No Poisson distribution complexity — constant rate is simpler and stronger. No per-device configuration — one policy, mandatory.

---

## 9. DID Resolution Privacy

**Question:** How should the protocol protect against metadata leakage during DID resolution?

**Background:** Resolving a did:dht identifier requires querying the Mainline DHT. DHT queries are visible to routing nodes along the query path. A DHT node that sees Alice querying Bob's DID learns that Alice is interested in Bob. Over time, DHT routing nodes can build a social graph of who resolves whom.

**Options:**

**A. Local DHT node.** Each SCP client runs a local Mainline DHT node. The client participates in DHT routing for all identifiers (not just SCP DIDs). DID resolution queries blend with normal DHT routing traffic — a DHT routing node can't distinguish "Alice is resolving Bob's DID" from "Alice's DHT node is routing a query on behalf of someone else."

Cost: Running a DHT node requires maintaining a routing table, handling incoming queries, and participating in node discovery. This is lightweight (the Mainline DHT has minimal resource requirements) but adds a background process. On mobile, this conflicts with OS power management.

Privacy: Good. DHT queries become indistinguishable from DHT routing. But Alice's DHT node still makes queries to specific DHT regions, which can be correlated with the identifiers stored in those regions if the observer has sufficient DHT topology knowledge.

**B. Tor-routed DHT queries.** DID resolution queries are routed through Tor. The DHT node serving the response sees a Tor exit node, not Alice's IP. Alice's ISP sees Tor traffic, not DHT queries.

Cost: Tor adds 2-5 seconds per query. First-contact resolution of a new DID becomes noticeably slower. Subsequent resolutions can be cached.

Privacy: Strong. Tor hides Alice's IP from DHT routing nodes and hides the DHT query from Alice's ISP.

**C. DHT resolution proxy.** Similar to the relay proxy (question #6B). Alice sends DHT queries to a proxy, which performs the resolution and returns the result. The proxy sees Alice's IP + the DID she's resolving. The DHT sees the proxy's IP.

Cost: Additional latency. Proxy infrastructure. Proxy becomes a metadata aggregation point.

Privacy: Hides Alice's IP from the DHT. But the proxy sees the full query — who is resolving which DID. If the proxy is compromised or malicious, it's worse than no protection.

**D. Batch/prefetch resolution.** The client periodically resolves a batch of DIDs including the ones it actually needs plus random ones. This provides k-anonymity — an observer sees the client resolving N DIDs and can't determine which ones the client actually cares about.

Cost: Bandwidth for unnecessary resolutions. DHT load from gratuitous queries.

Privacy: Moderate. The set of "real" DIDs is hidden in a larger set. Effectiveness depends on the batch size and how well the dummy DIDs are selected.

**E. No resolution privacy.** Accept that DHT queries reveal interest in specific identifiers. The Mainline DHT is large and noisy enough that SCP-specific queries are a small fraction of total DHT traffic.

**Analysis:**

The practical question is whether DHT resolution metadata is a meaningful attack vector. The Mainline DHT has millions of nodes and handles enormous query volume for BitTorrent. SCP DID resolution is a tiny fraction of this traffic. An attacker would need to operate many DHT nodes in the right part of the keyspace to observe Alice's queries — possible for a well-resourced adversary, but expensive.

A local DHT node (A) is the most practical mitigation for desktop/workstation clients. It provides meaningful privacy at low cost. Mobile clients can use cached resolution with periodic background updates.

**Suggestion: Local DHT node on persistent devices. Aggressive caching everywhere. Tor-routed resolution on mobile.**

This mirrors the connection privacy split (#6) — persistent devices and mobile devices have different profiles and get different mechanisms.

1. **Desktop / workstation / server: local Mainline DHT node, mandatory.** The client participates in the DHT as a routing node. DID resolution queries become indistinguishable from DHT routing traffic. The DHT node runs as part of the SDK's background process — it's lightweight (Mainline DHT nodes use minimal resources) and provides strong resolution privacy at zero additional infrastructure cost. The DHT is existing infrastructure with millions of nodes. Running a node is participation, not dependency.

2. **Mobile: Tor-routed DHT queries.** Mobile can't run a persistent DHT node (OS kills background processes). Instead, when the SDK needs to resolve a DID, it routes the DHT query through Tor. The DHT sees a Tor exit node, not the mobile device. Latency: 2-5 seconds per resolution. Acceptable because resolution is infrequent — you resolve a DID once on first contact, then cache.

3. **Aggressive caching everywhere.** DID documents are cached locally with their BEP44 sequence numbers. The SDK refreshes cached documents periodically (recommended: every 24 hours for active contacts, every 7 days for inactive). Stale documents are detected by sequence number comparison — if the cached sequence is lower than the resolved sequence, the document has been updated. Key change alerts (§9.11) trigger immediate re-resolution.

4. **No batch/prefetch resolution.** Batch queries add DHT load without strong privacy guarantees (the batch contents can be statistically analyzed). The local DHT node (#1) and Tor routing (#2) provide better privacy with less waste.

5. **No resolution proxy.** Same reasoning as #6 — proxies are new infrastructure that becomes a metadata aggregation target. Tor and local DHT nodes use existing infrastructure with no operator dependency.

Caching interaction with freshness: the SDK trusts cached documents until either (a) the periodic refresh interval elapses, (b) a key change alert is received, or (c) an MLS operation fails with a credential mismatch (indicating the key has rotated). On any of these triggers, the SDK re-resolves via DHT. Cached documents with valid sequence numbers are trusted without re-resolution — BEP44 sequence numbers prevent stale document attacks.

---

## 10. Relay Query Privacy

**Question:** Can the protocol prevent relays from learning which contexts a client subscribes to?

**Background:** When a client connects to a relay and subscribes to a context's messages, the relay learns: this client cares about this context. Combined with IP/connection metadata, the relay can map clients to contexts. Over time, the relay builds a complete view of which clients participate in which contexts it hosts.

Per-context pseudonyms (question #7) partially mitigate this — the relay sees subscriptions for pseudonyms rather than DIDs, so it can't link subscriptions to identity. But the relay still sees which pseudonyms subscribe to which contexts. If the relay also handles the context's messages, it can link the subscribing pseudonym to the sending pseudonym within that context.

**Options:**

**A. Download-everything-filter-locally.** The client downloads all messages from the relay (not just its contexts) and filters locally. The relay doesn't know which contexts the client cares about.

Cost: Bandwidth-prohibitive at scale. If a relay hosts 10,000 contexts, the client downloads all of them to hide which one it wants. Not viable.

**B. Private Information Retrieval (PIR).** The client queries the relay using a PIR scheme — a cryptographic protocol where the relay responds with the requested data without learning what was requested. The relay processes the query honestly (it can be verified) but learns nothing about which context was queried.

Cost: PIR is computationally expensive. Current PIR schemes have significant server-side cost (the relay must perform work proportional to the entire database for each query). Single-server PIR is expensive; multi-server PIR requires non-colluding servers (trust assumption). SealPIR, SimplePIR, and other recent schemes reduce costs but remain impractical for real-time messaging at scale.

**C. Relay set partitioning.** Each context is assigned to a different relay (or small set of relays). The client connects to different relays for different contexts. No single relay sees the client's full context set. Combined with per-context pseudonyms, each relay sees a different pseudonym subscribing to a different context.

Cost: Requires more relay connections. The client must manage connections to many relays. Not all contexts may have suitable relays in the desired partition. Doesn't prevent the relay from linking the pseudonym to the context — just limits the scope.

Privacy: Moderate. No single relay sees the full picture. But an adversary operating multiple relays can correlate.

**D. Subscription mixing.** The client subscribes to its real contexts plus a set of decoy contexts. Messages from decoy contexts are received and silently discarded. The relay sees a larger set of subscriptions and can't determine which are real.

Cost: Bandwidth for decoy context messages. The client must know about decoy contexts to subscribe to them. The effectiveness depends on the decoy set size.

Privacy: Moderate (k-anonymity). The relay knows the client subscribes to N contexts but doesn't know which subset is real.

**E. Accept the leak.** The relay knows which contexts the client subscribes to. Mitigate via relay set diversity (different relays for different contexts, as in C) and per-context pseudonyms (question #7). Accept that individual relays have partial visibility.

**Analysis:**

Full relay query privacy (PIR) is currently impractical for real-time messaging. The research is progressing but not ready for production.

The practical approach for v1 is a combination of:
- Per-context pseudonyms (question #7) so relays can't link subscriptions to identities
- Relay set partitioning (C) so no single relay sees all contexts
- Subscription mixing (D) for additional k-anonymity within each relay

This doesn't provide perfect query privacy but significantly raises the cost of surveillance. The protocol structures should be designed to support PIR when it becomes practical — meaning the subscription interface should be abstract enough to swap in a PIR-based implementation later.

**Suggestion: Per-context pseudonyms (#7) + mandatory relay set partitioning + subscription mixing. No PIR.**

PIR is a research-grade technology that's not ready for production messaging. Pursuing it would mean either shipping something that doesn't work well or blocking on unsolved computer science. Neither is acceptable. Instead, combine three practical mechanisms that together provide strong relay query privacy:

1. **Per-context pseudonyms (from #7) are the foundation.** The relay sees subscriptions for pseudonyms, not DIDs. It can't link "the pseudonym subscribing to context A" to "the pseudonym subscribing to context B" because they're different, unlinkable identifiers. This alone breaks the relay's ability to build a per-identity context graph.

2. **Relay set partitioning, mandatory.** Each context SHOULD use a different relay (or small set of relays) from the client's other contexts. The SDK distributes contexts across relays to minimize overlap. The relay assignment is determined by the context creator and published in context metadata. No single relay sees the full set of contexts any identity participates in.

   Implementation: when a context is created, the creator selects relay(s) from the available pool. The selection algorithm avoids relays that already host other contexts the creator participates in. This isn't always possible (limited relay availability), but the SDK does its best. The client connects to different relays for different contexts — each relay sees one (or few) pseudonyms from this client, subscribing to one (or few) contexts.

3. **Subscription mixing, mandatory.** When connecting to a relay, the client subscribes to its real context(s) on that relay PLUS a set of decoy context IDs. The relay delivers messages for all subscribed contexts. The client silently discards messages for decoy contexts. The decoy set should be ~3-5x the real set size (e.g., if subscribing to 2 real contexts on this relay, subscribe to 6-10 decoy contexts).

   Decoy selection: the SDK maintains a list of known context IDs (observed through relay metadata, shared by other clients, or generated randomly if the relay supports arbitrary subscriptions). Decoy contexts should have similar activity levels to real contexts — subscribing to dead contexts as decoys is trivially detectable.

Combined effect: the relay sees a pseudonym (unlinkable to identity) subscribing to N contexts (most of which are decoys), on a relay that hosts only a fraction of the client's total context set. The relay can't determine the client's identity, can't determine which subscriptions are real, and can't see the client's full context set. An adversary operating multiple relays can correlate connection metadata (IP, timing), but Tor (#6) mitigates this on mobile, and persistent connections + cover traffic (#8) mitigate on desktop.

This is not perfect privacy. A sufficiently resourced adversary operating many relays and performing long-term traffic analysis can degrade the guarantees. But it's strong enough that relay-based surveillance becomes expensive and unreliable — which is the practical goal. The protocol structures (pseudonyms, partitioning, subscription interface) are designed so that stronger mechanisms (PIR, better mixing) can be swapped in as they mature.

---

## Summary: Decision Dependencies

Some decisions depend on others:

```
#2 (Envelope opacity) ──► #7 (Per-context pseudonyms)
                              Both affect what the relay sees in the outer envelope.

#7 (Per-context pseudonyms) ──► #10 (Relay query privacy)
                                    Pseudonyms partially mitigate query privacy.

#6 (Connection privacy) ──► #9 (DID resolution privacy)
                                Both address IP-level metadata.

#3 (Message size) + #8 (Cover traffic) ──► Combined traffic analysis defense.
                                            Both address relay-side statistical analysis.

#4 (A2A) is independent of metadata privacy decisions but affects protocol scope significantly.

#5 (Sender-side blocking) is independent of all others.

#1 (Push opacity) is independent — simple mandate.
```

Recommended decision order:
1. Push opacity (#1) — simple, no dependencies
2. A2A (#4) — highest architectural impact, independent of metadata decisions
3. Sender-side blocking (#5) — needed for implementation, independent
4. Envelope opacity (#2) — foundational for metadata privacy
5. Per-context pseudonyms (#7) — depends on #2
6. Message size (#3) — independent but pairs with #8
7. Connection privacy (#6) — independent
8. Cover traffic (#8) — independent but pairs with #3
9. DID resolution privacy (#9) — relates to #6
10. Relay query privacy (#10) — depends on #7
