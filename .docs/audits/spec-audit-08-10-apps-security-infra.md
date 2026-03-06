---

# SCP Specification Audit: Unspecified Details in Sections 8, 9, and 10

## Section 8: Products and Apps in the Graph

---

### [8.4] Capability Declaration Has No Wire Format

- **Category**: Missing wire format details
- **Location**: Section 8.4
- **What's missing**: The section describes the capability declaration as "a structured, machine-readable manifest" but provides zero wire format. No JSON schema. No field names. No version envelope. No example beyond pseudocode fragments like `"I need: messaging, member_list, tool_invoke(tool_a, tool_b)"`. The open-questions file (00-open-questions.md) marks this resolved by saying it uses "JSON Schema (MCP-compatible)" with "resource URIs (`scp:ctx:{context_id}/{capability}`)" but no actual schema definition exists anywhere.
- **Why it matters**: An implementor cannot build capability declaration parsing, validation, or exchange without guessing the format. Two independent implementations will produce incompatible declarations. Since the declaration is described as the "boundary that makes generated apps safe," this is a security-relevant gap -- the safety boundary has no concrete shape.
- **Severity**: HIGH

---

### [8.4] Capability Declaration Validation Process Undefined

- **Category**: Underspecified algorithms
- **Location**: Section 8.4
- **What's missing**: "The protocol validates the declaration against the context's capability ceiling and the user's granted permissions, then provides exactly what was requested." How? At what point in the lifecycle is this validation performed -- at app registration, at connection time, or per-invocation? What happens when validation fails partially (app requests 5 capabilities, 3 are granted, 2 are denied)? Is it all-or-nothing or partial grant? The pseudocode shows a binary granted/denied, but the text says "provides exactly what was requested" (implying full match required).
- **Why it matters**: Partial grant vs. all-or-nothing is a critical design decision. An app that receives partial capability without knowing which capabilities were denied could malfunction or expose unexpected behavior.
- **Severity**: MEDIUM

---

### [8.4] Capability Declaration Versioning Has No Mechanism

- **Category**: Missing constants/defaults
- **Location**: Section 8.4, bullet 4
- **What's missing**: "Declarations carry a protocol version. Apps built against older declarations continue to work. Forward compatibility is a protocol constraint." No version format (SemVer? integer?). No backward compatibility rules. No deprecation mechanism. No specification of what "continue to work" means when a newer protocol version removes a capability the old declaration references.
- **Why it matters**: Without version negotiation rules, protocol upgrades can silently break apps or silently grant capabilities that didn't exist when the app was declared.
- **Severity**: MEDIUM

---

### [8.3] App State Portability Has No Protocol Mechanism

- **Category**: Missing edge cases
- **Location**: Section 8.3
- **What's missing**: "App-specific state may or may not transfer -- that depends on the apps, not on the protocol." This correctly identifies app state as out-of-scope, but provides no guidance, interface, or convention for apps that WANT to make their state portable. No recommended serialization format, no app state metadata in context state, no migration protocol sketch.
- **Why it matters**: Without even a recommended pattern, every app will invent its own migration story, making the "app switching" promise hollow in practice. Two apps building on the same context type will store state in incompatible formats with no discovery mechanism.
- **Severity**: LOW

---

### [8.5] MCP Namespace Collision Resolution Unspecified

- **Category**: Missing edge cases
- **Location**: Section 8.5
- **What's missing**: "Multi-context as namespaced MCP tools" -- tools are namespaced by context, e.g., `context_a/send_message`. But: what character separates context from tool name? What if a tool name contains that separator? What if two contexts register tools with identical names? What happens when a context ID changes (child context spawned from template)? No namespace format specification, no collision resolution rules.
- **Why it matters**: Namespace collision breaks agent tool selection. An agent calling `context_a/send_message` when two contexts offer `send_message` needs deterministic routing.
- **Severity**: MEDIUM

---

### [8.5] Agent-Side Capability Filtering Security Boundary Undefined

- **Category**: Security-relevant omissions
- **Location**: Section 8.5
- **What's missing**: "Capability filtering happens at the agent." The agent exposes only permitted tools. But: what prevents a compromised or malicious agent from calling tools it filtered out of the MCP surface? The filtering is described as an MCP presentation concern, not a protocol enforcement point. If the agent has MLS membership, it has access to all context messages regardless of what it exposes via MCP. There is no enforcement at the protocol level -- it is entirely trust-the-agent.
- **Why it matters**: The text says "tools the agent lacks capability for are never surfaced to the model" but the agent software itself has full context access. A compromised agent runtime can invoke any tool regardless of its MCP surface presentation. The "boundary that makes generated apps safe" is the agent's code quality, not the protocol.
- **Severity**: MEDIUM

---

## Section 9: Security Model

---

### [9.10.3/9.10.6] Bucket Size Contradiction

- **Category**: Cross-reference inconsistencies
- **Location**: Section 9.10.3 (line 540) vs. Section 9.10.6 (line 608)
- **What's missing**: Section 9.10.3 defines bucket sizes as: `256B, 1KB, 4KB, 16KB, 64KB, 256KB` (factor-of-4 progression). Section 9.10.6 defines padding buckets as: `256, 512, 1024, 2048, 4096 bytes` (power-of-2 progression, only 5 buckets, max 4KB). These are fundamentally different padding schedules applied to ostensibly the same data. The first covers up to 256KB; the second covers up to 4KB. The first uses factor-of-4 jumps; the second uses factor-of-2 jumps.
- **Why it matters**: Two implementations following different sections will produce differently-sized blobs for the same plaintext, making message size a distinguishing signal. A message that is 5KB would pad to 16KB under section 9.10.3 but would need to be chunked under section 9.10.6's scheme (max 4096). This directly undermines the traffic analysis resistance the padding is supposed to provide. An implementor has no way to know which is canonical.
- **Severity**: CRITICAL

---

### [9.10.3] Chunking Algorithm for Oversized Messages Unspecified

- **Category**: Underspecified algorithms
- **Location**: Section 9.10.3 (line 542)
- **What's missing**: "Messages larger than 256KB are chunked into 256KB blocks." No chunking format specified. No chunk header. No sequence numbering for chunks. No reassembly protocol. No handling for lost chunks. No indication of whether chunks are independently MLS-encrypted or collectively encrypted then split. No maximum message size before chunking.
- **Why it matters**: Chunking requires a wire format (chunk index, total chunks, parent message ID), an ordering guarantee, and a reassembly timeout. Without these, large message support is unimplementable. If chunks are independently encrypted, a relay can selectively suppress individual chunks (cheaper than suppressing entire messages).
- **Severity**: HIGH

---

### [9.3] Earned Capacity Parameters Completely Undefined

- **Category**: Missing constants/defaults
- **Location**: Section 9.3
- **What's missing**: "New identities start with limited capabilities -- restricted context creation, limited participation slots, constrained tool invocation rates. Capacity grows through participation history, participation records, and time." No concrete defaults for any of these limits. How many contexts can a new identity create? What is the initial participation slot count? What tool invocation rate applies to a brand-new DID? How does capacity grow -- linearly, logarithmically? What are the thresholds? The open-questions file says this is resolved and "scoring is not protocol-level" but the protocol specifies earned capacity as a defense mechanism with zero concrete parameters.
- **Why it matters**: Without protocol-level defaults, a new deployment has zero Sybil resistance at Layer 1. Every implementation must invent its own thresholds, making the security guarantee non-uniform and the interoperability story broken (context A says "you need 30 days of history" using its custom formula; context B says "you need 5 contexts" using a different formula -- neither can validate the other's claim). The spec delegates to "product-layer" but provides no protocol-level floor.
- **Severity**: HIGH

---

### [9.2.1] Tool Interface Rate Limit Defaults Missing

- **Category**: Missing constants/defaults
- **Location**: Section 9.2.1, item 3 (line 69)
- **What's missing**: "Each context enforces rate limits on both inbound and outbound tool calls within a sliding time window." No default rate. No window size. No specification of what the rate limit unit is (calls/second? calls/minute?). No maximum or minimum values. No behavior when rate is exceeded (drop? queue? error response?).
- **Why it matters**: Rate limiting is described as the primary defense against chained tool call amplification. Without defaults, a new context has no rate limiting until an administrator manually configures one. The amplification attack described in the spec is unmitigated by default.
- **Severity**: HIGH

---

### [9.2.1] Velocity Limit for Context Infection Undefined

- **Category**: Missing constants/defaults
- **Location**: Section 9.2 (line 29)
- **What's missing**: "velocity limits on propagation (content bridged N times in M minutes is flagged)" -- N and M are never defined. No default. No specification of what "flagged" means (alert? block? rate-limit?). No mechanism for measuring or tracking this velocity.
- **Why it matters**: This is cited as a mitigation for context infection attacks but has zero implementation guidance.
- **Severity**: MEDIUM

---

### [9.2.1] Invitation Rate Limit Defaults Missing

- **Category**: Missing constants/defaults
- **Location**: Section 9.2.1, item 6 (line 101)
- **What's missing**: "The SDK rate-limits inbound invitations per source DID and globally." No per-DID rate. No global rate. No queue depth limit ("queued with decreasing priority" -- but how deep is the queue?). No specification of the priority decay function.
- **Why it matters**: Without concrete rate limits, the human coordination bottleneck defense described in the same section is advisory only.
- **Severity**: MEDIUM

---

### [9.7.2] Grace Window Condition (a) Is Unprovable

- **Category**: Missing edge cases
- **Location**: Section 9.7.2 (line 304)
- **What's missing**: Grace window closes at the shorter of "(a) all members have sent at least one message in the new epoch, or (b) 30 seconds." Condition (a) requires knowing that ALL members have sent in the new epoch. But: how does a client know it has received from all members? It knows the member list, but it cannot distinguish "member hasn't sent yet" from "message is in transit" from "message was suppressed." In a group of 50 members where 10 are offline, condition (a) never triggers, and the client falls back to (b) -- making condition (a) effectively dead code for any non-trivial group.
- **Why it matters**: This is a correctness concern, not a security concern (condition (b) is the real bound), but the spec presents (a) as a meaningful condition when it is practically useless for groups with offline members.
- **Severity**: LOW

---

### [9.8.2] Dedup Cache Size Is Ambiguous

- **Category**: Vague requirements
- **Location**: Section 9.8.2 (line 378)
- **What's missing**: "Cache size: bounded by a sliding window of the most recent 10,000 envelopes or 24 hours, whichever is larger." Ambiguous: does "whichever is larger" mean the larger of the two sets (union), or "keep at least 10,000 AND keep at least 24 hours of history"? If I receive 100,000 envelopes in 1 hour, do I keep all 100,000 (because 24 hours hasn't elapsed and that's "larger")? Or do I keep 10,000 (because that's the count limit and it's "larger" than the time-bounded count)?
- **Why it matters**: This determines memory usage under load. An implementation that interprets "whichever is larger" as "keep both constraints" could consume unbounded memory during a burst. The intent is probably "at least 10,000 or all envelopes from the last 24 hours, whichever retains more entries" but it must be unambiguous.
- **Severity**: MEDIUM

---

### [9.8.5] Reorder Buffer Has No Memory Bound Per Context

- **Category**: Missing constants/defaults
- **Location**: Section 9.8.5 (lines 412-418)
- **What's missing**: The reorder buffer is "bounded at 100 messages per sender per context." For a context with 1000 members, that is up to 100,000 buffered messages. No aggregate bound across all senders in a context. No aggregate bound across all contexts. A malicious member set (or a large group with intermittent connectivity) could exhaust device memory through legitimate-looking out-of-order delivery.
- **Why it matters**: On mobile devices (constrained memory), 1000 senders x 100 messages x average_message_size could be significant. No per-context or global aggregate bound is specified.
- **Severity**: MEDIUM

---

### [9.9.3] Consistency Checkpoint Event Count Tolerance Underspecified

- **Category**: Vague requirements
- **Location**: Section 9.9.3 (line 477)
- **What's missing**: "eventCount: Must match (within tolerance for in-flight messages). Divergence of more than 5 events indicates inconsistency." Why 5? Is this a hard constant or a suggested default? Should it scale with context activity (a context with 1000 events/minute might have more than 5 in-flight at checkpoint time)? What happens when divergence is exactly 5 -- consistent or inconsistent?
- **Why it matters**: An overly tight tolerance causes false positives in active contexts. An overly loose tolerance lets equivocation go undetected. The spec gives no guidance on tuning.
- **Severity**: LOW

---

### [9.9.3] Equivocation Response Is Undefined

- **Category**: Undefined error/failure behavior
- **Location**: Section 9.9.3 (line 481)
- **What's missing**: "The context's governance model handles the response." No default response for any governance model. No specification of what "handles the response" means. Does the governance model automatically switch relays? Eject a relay from the relay set? Alert members? Freeze the context? Nothing is specified. The detection mechanism is well-specified; the response mechanism is a void.
- **Why it matters**: Detection without response is monitoring, not defense. If equivocation is detected but the protocol specifies no default action, implementations will vary between "log and ignore" and "halt the context."
- **Severity**: HIGH

---

### [9.9.4] MLS Commit Recovery Lacks Timeout

- **Category**: Missing constants/defaults
- **Location**: Section 9.9.4 (line 493)
- **What's missing**: Members who detect they are behind on epochs "MUST request the missing Commit from other members via directed MLS application messages or from alternative relays." No timeout for this recovery. No retry limit. No specification of what happens if the Commit is permanently lost (all relays corrupted and no member responds). No fallback to group state reset or Tier 3 re-join.
- **Why it matters**: Without a recovery timeout, a client stuck in epoch N while the group is at epoch N+3 could retry indefinitely. The spec references ADR-029's three-tier sync but doesn't bind the Commit recovery protocol to it.
- **Severity**: MEDIUM

---

### [9.10.4] Pseudonym Derivation Uses Ed25519 keygen From Non-Key-Material

- **Category**: Security-relevant omissions
- **Location**: Section 9.10.4 (line 549-552)
- **What's missing**: `context_seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")` then `context_keypair = Ed25519_keygen(context_seed[0..32])`. The spec uses an HMAC output (a PRF output) as seed material for Ed25519 key generation. This is fine for pseudonym derivation, but the spec says "identity_key_material" without defining what this is. Is it the Ed25519 private key bytes? The public key bytes? An HSM-derived key handle? Line 560 says "For software keys, the HMAC uses the raw Ed25519 public key bytes" -- but public key bytes as HMAC key material for pseudonym derivation means anyone with the public key (everyone) can derive the pseudonym. The pseudonym is then not a secret -- it is publicly computable from (public_key, context_id).
- **Why it matters**: If the pseudonym is derivable from the public key, any party who knows both the DID and the context_id can compute the pseudonym. This means: (1) a relay that knows a DID and suspects a context_id can verify membership by computing the pseudonym and checking subscriptions, and (2) cross-context correlation is broken only if the context_id is secret, but context_ids are referenced in metadata routing (`SHA-256(context_id || "scp-metadata")` per line 561). The spec says pseudonyms are "unlinkable across contexts" -- but they are fully linkable if you know the context_id.
- **Severity**: HIGH

---

### [9.10.4] Metadata Routing ID Leaks Context ID Existence

- **Category**: Security-relevant omissions
- **Location**: Section 9.10.4 (line 561)
- **What's missing**: `metadata_routing_id = SHA-256(context_id || "scp-metadata")` -- this is publicly derivable from `context_id`. Anyone who knows a context_id can query relays for its metadata without being a member. Combined with the previous finding (pseudonyms derivable from public key + context_id), this means a relay operator who knows a context_id can compute the pseudonym for every known DID and check which ones are subscribed. The spec acknowledges relay metadata visibility but not this specific enumeration attack.
- **Why it matters**: An attacker who knows (or guesses) a context_id can enumerate which DIDs are members by computing pseudonyms for all known DIDs and checking which routing_ids have active subscriptions. This is a membership oracle.
- **Severity**: HIGH

---

### [9.10.4.1] Pseudonym Rotation Has No Maximum Epoch Gap

- **Category**: Missing constants/defaults
- **Location**: Section 9.10.4.1 (lines 563-578)
- **What's missing**: During pseudonym rotation, the client subscribes to both old and new routing_ids for a "grace period (recommended: 2x the context's blob TTL)." But what is the maximum number of pseudonym epochs a client can be behind? If a client is offline for months and the context has rotated pseudonyms 50 times, does the client subscribe to 50 old routing_ids? No maximum epoch gap or catch-up mechanism is specified.
- **Why it matters**: Memory and subscription costs scale linearly with missed rotations. A returning client might need to subscribe to an unbounded number of old routing_ids.
- **Severity**: MEDIUM

---

### [9.10.6] Cover Traffic Real/Dummy Flag Is Single-Byte Inside Encrypted Payload

- **Category**: Security-relevant omissions
- **Location**: Section 9.10.6 (line 606)
- **What's missing**: The single-byte flag (`REAL_FLAG = 0x01`, `DUMMY_FLAG = 0x00`) inside the encrypted payload distinguishes real from dummy messages. This is fine from a relay perspective (relay can't see inside). But: the flag is a single byte with no integrity binding. After MLS decryption, a group member sees the flag. A compromised member could rewrite the flag in a forwarded message. More importantly: the spec doesn't specify WHERE in the plaintext the flag goes (first byte? last byte?) or how it interacts with the rest of the message format (is it inside the sender-key layer? inside the MLS layer? before padding?).
- **Why it matters**: Without precise placement in the processing pipeline, implementations will disagree on where to check the flag, potentially causing real messages to be discarded as dummies or vice versa.
- **Severity**: MEDIUM

---

### [9.11] Key Continuity Fingerprint Uses Only 128/200 Bits

- **Category**: Missing constants/defaults
- **Location**: Section 9.11 (lines 671-673)
- **What's missing**: The fingerprint hash is 256 bits but display formats use partial values: 12-word mnemonic (128 bits), 60-digit decimal (200 bits), QR code (256 bits). No specification of how to extract the 128 or 200 bits. First 128 bits? Truncation? Folding? For the decimal format: 60 decimal digits encode approximately 199.3 bits -- how is the 200-bit value encoded into exactly 60 digits?
- **Why it matters**: Two implementations that extract different bit ranges will produce different mnemonics for the same key pair, causing legitimate verification to fail.
- **Severity**: MEDIUM

---

### [9.12] Compromise Recovery Has No Step Failure Handling

- **Category**: Undefined error/failure behavior
- **Location**: Section 9.12 (line 709)
- **What's missing**: The step ordering section says "failure in one context does not block recovery in other contexts" and "The SDK retries failed contexts independently" -- but no retry limit, no retry backoff interval, no maximum recovery time, and no specification for what happens if step 1 (key rotation) succeeds but step 3 (UCAN revocation) fails permanently. Are there partially-recovered states that are valid? Can a DID be in a state where the key is rotated but old UCANs are still active in some contexts?
- **Why it matters**: Partial recovery is a real scenario (device goes offline mid-recovery, relay is unreachable for one context). The protocol must define what "partially recovered" means and whether it is safe.
- **Severity**: MEDIUM

---

### [9.14] Clock Skew Direction Asymmetry

- **Category**: Missing edge cases
- **Location**: Section 9.14 (line 731)
- **What's missing**: "Messages with timestamps more than 5 minutes in the future are rejected." No past-bound rejection. Line 382 says "The past-bound is relative, not absolute, to handle offline delivery: if Bob comes online after 3 hours, he accepts messages from the past 3 hours." But this means there is effectively NO past-bound at all -- a message from 30 days ago would be accepted if the sender was offline for 30 days. The spec says timestamps from a single sender must not regress, but a compromised relay could delay delivery of a message indefinitely, and the recipient has no way to reject it on age alone.
- **Why it matters**: Without a past-bound, stale messages can be delivered at arbitrary times. This interacts with UCAN expiry -- a UCAN that expired 23 hours ago is no longer valid, but the message it authorized might still be accepted if delivery was delayed. The spec needs to address the interaction between message age tolerance and capability expiry.
- **Severity**: MEDIUM

---

### [9.15] Destruction Attestation Has No Verification Protocol

- **Category**: Missing conformance criteria
- **Location**: Section 9.15 (lines 750-768)
- **What's missing**: `KeyDestructionAttestation` is signed and published. But: who verifies them? Where are they published (which relay, under which routing_id)? How do other members discover them? Is there a timeout for receiving attestations from all members? What happens if a member never publishes one (offline, crashed, malicious)? No collection protocol, no quorum requirement, no timeout.
- **Why it matters**: Without a collection protocol, destruction attestations exist but are never systematically verified. The spec implies they are useful for trust decisions but provides no mechanism for collecting or evaluating them.
- **Severity**: MEDIUM

---

### [9.16.2] SenderKeyRequest Signature Does Not Bind context_id

- **Category**: Security-relevant omissions
- **Location**: Section 9.16.2 (line 794)
- **What's missing**: `SenderKeyRequest { requester_did, sender_did, epoch, wrapping_pubkey, signature }` -- the signature is described but its scope is not fully specified. The `SenderKeyEpochAdvance` signature covers `context_id || sender_did || "key_epoch" || epoch` (line 792). But the `SenderKeyRequest` signature scope is not specified -- just "verifies the signature." Does the SenderKeyRequest signature also bind context_id? If not, a SenderKeyRequest for context A could be replayed in context B.
- **Why it matters**: Cross-context replay of key requests could trick a sender into distributing keys to the wrong context. The signature must bind context_id to prevent this. My memory notes flag this exact pattern: "Watch for functions that omit context_id from their hash (e.g. key request hashes)."
- **Severity**: HIGH

---

### [9.16.3] Block Notification Wire Format Is JSON-In-MLS

- **Category**: Cross-reference inconsistencies
- **Location**: Section 9.16.3 (line 815)
- **What's missing**: The block notification uses a JSON-like format: `{"type": "block", "blocker": "...", ...}`. But the rest of the protocol uses MessagePack for wire encoding (ADR-004, section 17.5). Is this JSON literal inside MLS? MessagePack? The format is shown as JSON but never stated to be JSON. If it is MessagePack, the field names should match the serialization convention. This is the only place in the security spec that shows a message body as JSON.
- **Why it matters**: Serialization format inconsistency causes interoperability failure. If one implementation serializes as JSON and another as MessagePack, block notifications fail silently.
- **Severity**: MEDIUM

---

### [9.16.7] SDK-Mandated Destruction Timing Constraint May Deadlock

- **Category**: Missing edge cases
- **Location**: Section 9.16.7 (line 870)
- **What's missing**: "Destruction MUST occur before the SDK processes any subsequent messages. The block notification handler is synchronous with respect to message processing." If the destruction involves deleting from a database (potentially slow on mobile), and the message processing pipeline is synchronous, a slow deletion could block all message processing for the context. No timeout on the destruction operation. No specification of whether "synchronous" means "blocks the thread" or "holds a logical lock."
- **Why it matters**: On resource-constrained devices, synchronous destruction of cached plaintext from a prolific sender could take seconds, during which all message processing halts. This is a DoS vector -- send 10,000 messages, then block, and the recipient's SDK freezes for seconds during destruction.
- **Severity**: MEDIUM

---

### [9.17.1] AccessKeyRequest Replay Window Inconsistency

- **Category**: Cross-reference inconsistencies
- **Location**: Section 9.17.1 (line 921)
- **What's missing**: "The timestamp prevents replay (requests older than 30 seconds are rejected)." But the UCAN nonce deduplication window is 24 hours (section 9.5, line 218), the clock skew tolerance is 5 minutes (section 9.14), and the sender key epoch grace period is also 30 seconds (section 9.16.2). The 30-second replay window for access key requests means a clock skew of just 31 seconds between two members causes all access key requests to be rejected. The 5-minute clock skew tolerance in section 9.14 is 10x larger than this 30-second window.
- **Why it matters**: A 30-second replay window is tight enough to fail in production with normal clock drift. Two devices with 35 seconds of clock skew will be unable to exchange access keys, while all other protocol operations (which tolerate 5 minutes of skew) work fine. This is an inconsistency that will cause mysterious access key failures.
- **Severity**: HIGH

---

### [9.17.2] Access Key Generation Authority Ambiguous

- **Category**: Ambiguous state transitions
- **Location**: Section 9.17.2 (line 925)
- **What's missing**: "a fresh random 32-byte AES-256 access key is generated by the context creator (or the member who executed the `AddMember` governance action)." Who actually generates it? The context creator might not be online when a new member is added. Is it always the member who executed AddMember? What if AddMember is executed via governance vote (no single executor)? What if the admin is offline -- does the new member join without an access key?
- **Why it matters**: Access key generation is a single point of failure. If the designated generator is offline, the new member cannot decrypt any content. The spec needs to specify fallback generators or a distributed generation protocol.
- **Severity**: MEDIUM

---

### [9.17.3] member_id Collision Probability Underspecified

- **Category**: Missing edge cases
- **Location**: Section 9.17.3 (line 951)
- **What's missing**: `member_id: [u8; 8]` -- "First 8 bytes of SHA-256(member_did)." The spec claims "collision probability for 8-byte hashes is negligible for context sizes up to millions of members." The birthday bound for 8-byte hashes is approximately `2^32 = 4 billion` before 50% collision probability. For 1 million members, collision probability is approximately `(10^6)^2 / (2 * 2^64) ~ 0.003%`. At 10 million members, it rises to ~0.3%. No collision resolution mechanism is specified. What happens when two members have the same `member_id`? The recipient scans linearly and... tries both? Takes the first match?
- **Why it matters**: In contexts with >10,000 subscribers (broadcast contexts), collision probability becomes non-negligible. A collision means a recipient might unwrap the wrong CEK and fail decryption without knowing why. No error recovery path exists.
- **Severity**: MEDIUM

---

### [9.17.5] Full Revocation Requires Coordinated Key Deletion

- **Category**: Underspecified algorithms
- **Location**: Section 9.17.5 (line 983)
- **What's missing**: "Delete the target's access key from all members' local stores." How? This requires sending a message to every member instructing them to delete a specific key. What happens if a member is offline? Do they delete on reconnect? What happens if a member misses the deletion message? Is there a confirmation protocol? Can the revoker verify that all members have deleted? What if a non-compliant client retains the key?
- **Why it matters**: Coordinated key deletion across a distributed system is a fundamentally hard problem. The spec states it as a simple operation but provides no protocol for ensuring it happens. A single member retaining the key defeats the "retroactive revocation" guarantee.
- **Severity**: HIGH

---

## Section 10: Infrastructure and Self-Hosting

---

### [10.3] Event Log Pruning Rules Explicitly Deferred

- **Category**: Missing constants/defaults
- **Location**: Section 10.3 (line 64)
- **What's missing**: "The protocol must define pruning rules (how old events are archived or summarized), checkpoint mechanisms (periodic Merkle roots that compress history), and availability requirements (does every device store the full tree, or can proofs be fetched on demand from relays or peers?)." This is the spec acknowledging it has not specified something critical. No pruning interval. No maximum log size. No checkpoint format. No proof-on-demand protocol.
- **Why it matters**: Without pruning, the event log grows without bound. The spec says "the protocol must define" these things but then does not define them. For a protocol that promises "device-as-node" (section 10.2), unbounded state growth is incompatible with mobile deployment.
- **Severity**: HIGH

---

### [10.4] Relay Reference Implementation Has No Conformance Test for Operational Behavior

- **Category**: Missing conformance criteria
- **Location**: Section 10.4 (line 87)
- **What's missing**: `blob_store_conformance!()` tests storage operations. `transport_conformance!()` tests transport operations. Neither tests: rate limiting behavior, connection limiting, abuse prevention, delivery jitter, bridge relay behavior, STUN service, or any operational characteristic. The spec says a production relay needs "reliable delivery, ordering, deduplication, rate limiting, and abuse prevention" but no conformance test covers these.
- **Why it matters**: Two relay implementations that pass conformance testing could have radically different behavior under adversarial load. One might rate-limit at 100 req/s, another at 10,000 req/s. One might have no abuse prevention. Conformance testing covers the happy path; production relays need adversarial testing.
- **Severity**: MEDIUM

---

### [10.7] Push Notification Registration Protocol Unspecified

- **Category**: Missing wire format details
- **Location**: Section 10.7 (lines 290-296)
- **What's missing**: How does the relay know to send a push notification? The spec says push payloads contain only a wake signal, but: who registers the push token with the relay? What is the registration protocol? How does the relay associate a push token with a routing_id subscription? How is the push token authenticated (preventing an attacker from registering their device token against a victim's routing_id to steal wake signals)? What happens when a push token expires?
- **Why it matters**: Push notification delivery is the ONLY mechanism for mobile message delivery. Without a registration protocol, mobile support is unimplementable.
- **Severity**: HIGH

---

### [10.8] Multi-Device Key Synchronization Unspecified

- **Category**: Security-relevant omissions
- **Location**: Section 10.8 (lines 300-306)
- **What's missing**: "Multi-device coordination... is a client-scope concern." But MLS membership is per leaf node, and the spec maps each "agent in context" to one leaf node (section 9.7.1). How does a user with 3 devices join one context? Three leaf nodes? One leaf node shared across devices? If three leaf nodes, the user appears as three members. If one shared leaf node, the MLS private key must be synchronized across devices -- which is itself a key management problem that requires a solution.
- **Why it matters**: MLS does not natively support multi-device. Each device needs its own leaf node (which means separate membership entries) or devices must share key material (which requires a secure sync protocol). Declaring this "client-scope" dodges a fundamental protocol design question that affects the member count, message encryption cost (O(N) where N now includes device count), and the user experience of "one identity, multiple devices."
- **Severity**: HIGH

---

### [10.9.1] Media Session Key Derivation Lacks Specification

- **Category**: Underspecified algorithms
- **Location**: Section 10.9.1 (line 323)
- **What's missing**: "MLS derives media session keys. The MLS group's key schedule exports keying material for the media session (MLS exporter, RFC 9420 section 8)." No exporter label specified. No exporter context specified. No key length specified. No specification of how the exported key maps to DTLS-SRTP keying (DTLS uses its own key exchange; injecting MLS-exported keys into DTLS-SRTP requires a specific integration mechanism that is not described).
- **Why it matters**: Without an exporter label and context, two implementations will derive different media keys for the same MLS group. The MLS-to-WebRTC key binding is the critical security property of this design -- if it is underspecified, the entire media security model is vapor.
- **Severity**: HIGH

---

### [10.12.1] NAT Traversal Tier Selection Has No Locking Mechanism

- **Category**: Missing edge cases
- **Location**: Section 10.12.1 (line 379)
- **What's missing**: "The SDK re-evaluates periodically (recommended: every 30 minutes) and on network change events." What happens during tier transition? If the relay is serving connections via Tier 1 (UPnP) and the SDK decides to switch to Tier 2 (STUN), there is a window where the DID document has been updated but peers are still connecting to the old address. No specification of how to drain connections before tier change. No specification of whether the old tier continues serving during DID document propagation delay.
- **Why it matters**: Tier transitions cause message loss during the propagation window. Peers connecting to the stale address will fail, and the relay has no way to redirect them because the old port mapping may already be released.
- **Severity**: MEDIUM

---

### [10.12.3] STUN Hole Punching Coordination Protocol Missing

- **Category**: Underspecified algorithms
- **Location**: Section 10.12.3 (line 426)
- **What's missing**: "Connection coordination: A peer resolving the self-hosted relay's DID document obtains the external address. For restricted NATs, the self-hosted relay must initiate a packet exchange with each connecting peer. The relay periodically sends keepalive packets to peers that have announced their intent to connect (via a coordination message through an intermediary relay)." No specification of this coordination message format. No specification of "intent to connect" signaling. No specification of which intermediary relay handles coordination. No specification of what happens if the intermediary relay is down.
- **Why it matters**: STUN hole punching for restricted NATs requires mutual packet exchange. Without a coordination protocol, peers behind restricted NATs cannot connect to self-hosted relays behind restricted NATs (both sides need to send first). The spec identifies the need but provides no wire format.
- **Severity**: HIGH

---

### [10.12.4] Bridge Registration Has No Deregistration Protocol

- **Category**: Missing edge cases
- **Location**: Section 10.12.4 (line 499)
- **What's missing**: "When the self-hosted relay disconnects, the bridge deregisters all its routing IDs." This implies implicit deregistration on connection close. But: what about explicit deregistration (relay moving to a different bridge)? What about stale registrations when the self-hosted relay crashes without clean disconnect? No keepalive or heartbeat for bridge registrations. No registration TTL. No explicit BRIDGE_DEREGISTER operation.
- **Why it matters**: If the self-hosted relay crashes (network failure, power loss), the bridge holds a stale registration indefinitely. Peers sending BRIDGE_DATA to this routing_id will succeed (from the bridge's perspective) but messages will never reach the self-hosted relay. No error is returned to the sender because the bridge has no way to detect the crashed relay until the TCP connection times out (which could be minutes).
- **Severity**: MEDIUM

---

### [10.12.4] Bridge Authentication Timestamp Replay Window

- **Category**: Security-relevant omissions
- **Location**: Section 10.12.4 (line 491)
- **What's missing**: The BRIDGE_REGISTER signature includes a timestamp with a 60-second replay window. But: there is no nonce. An attacker who captures a valid BRIDGE_REGISTER can replay it within 60 seconds to re-register the routing_id on a different bridge relay, hijacking traffic. The Ed25519 signature prevents forgery but not replay. The spec says "The timestamp is within 60 seconds of the server's current time" -- but server clock skew is not addressed. Two bridge relays with 30 seconds of clock drift effectively double the replay window.
- **Why it matters**: Replay of BRIDGE_REGISTER allows traffic hijacking within the 60-second window. A nonce or monotonic sequence number would close this.
- **Severity**: MEDIUM

---

### [10.12.6] ws:// Downgrade Rejection Has No Positive Test

- **Category**: Missing conformance criteria
- **Location**: Section 10.12.6 (line 540)
- **What's missing**: "The SDK MUST reject `ws://` relay URLs obtained from `.well-known/scp` or any non-DHT source." This is a critical security enforcement but has no specified conformance test. How does the SDK know the source of a relay URL? If a URL is loaded from a configuration file, is that "non-DHT"? What about URLs obtained from other SCP messages (a member sharing a relay recommendation)? The boundary between "DHT-discovered" and "non-DHT" is not sharply defined.
- **Why it matters**: A downgrade attack that injects `ws://` URLs through any non-DHT channel could expose metadata to network intermediaries. The enforcement boundary must be precisely defined.
- **Severity**: MEDIUM

---

### [10.13.1] Connection Budget LRU Eviction Can Kill Active Contexts

- **Category**: Missing edge cases
- **Location**: Section 10.13.3 (lines 692-698)
- **What's missing**: "LRU eviction. The least-recently-used connection... is closed." LRU is based on "last message send or receive timestamp." But a context could be active (user is reading) without sending or receiving new messages (the user is reading old messages from cache). The connection appears idle and gets evicted. The next incoming message for that context has no connection and triggers a re-establishment, potentially missing the message if it arrives during re-connection.
- **Why it matters**: LRU eviction based on transport-level activity does not account for application-level activity. A user actively reading a context could have its relay connection evicted.
- **Severity**: LOW

---

### [10.14.2] QUIC 0-RTT Replay Protection Delegated But Unspecified

- **Category**: Security-relevant omissions
- **Location**: Section 10.14.2 (line 722)
- **What's missing**: "0-RTT data has no replay protection (RFC 9001 section 9.2); SCP operations sent as 0-RTT MUST be idempotent or the relay MUST implement anti-replay measures." No specification of which SCP operations are idempotent. PUBLISH is not idempotent (it creates a new blob). SUBSCRIBE could be idempotent. QUERY is idempotent. DELETE is idempotent (deleting an already-deleted blob is a no-op). No specification of what "anti-replay measures" the relay should implement.
- **Why it matters**: If PUBLISH is sent as 0-RTT, a network attacker can replay it, causing duplicate message delivery. The spec should either prohibit PUBLISH in 0-RTT or specify the relay's anti-replay mechanism.
- **Severity**: HIGH

---

### [10.14.3] QUIC Probe Timeout Magic Number

- **Category**: Missing constants/defaults
- **Location**: Section 10.14.3 (line 734)
- **What's missing**: "The client MAY probe QUIC with a single initial packet; if no response within 3 seconds, it falls back to WebSocket without further QUIC attempts for that relay until the next `.well-known/scp` refresh." The 3-second timeout is a magic number. What is the `.well-known/scp` refresh interval? How long does the client avoid QUIC? If the refresh interval is 24 hours, a transient network issue blocks QUIC for 24 hours. No specification of the refresh interval.
- **Why it matters**: Without a refresh interval, the QUIC fallback could be permanent or effectively permanent.
- **Severity**: LOW

---

### [10.16.1] Constrained Device Has No Maximum Message Size

- **Category**: Missing constants/defaults
- **Location**: Section 10.16.1 (line 797)
- **What's missing**: "Recommended max blob size: 1024 bytes for single-datagram delivery." But this is a recommendation, not a requirement. No protocol-level enforcement of a maximum message size for constrained devices. No specification of what happens when a message exceeds the path MTU and DTLS fragmentation occurs. No maximum number of DTLS fragments per message.
- **Why it matters**: A constrained device with 1200-byte path MTU receiving a 256KB blob (the default max_blob_size) would need ~213 DTLS datagrams. No fragment reassembly timeout or maximum fragment count is specified, making this a resource exhaustion vector for constrained devices.
- **Severity**: MEDIUM

---

### [10.16.2] CoAP Observe Is Not Equivalent to SUBSCRIBE

- **Category**: Vague requirements
- **Location**: Section 10.16.2 (line 809)
- **What's missing**: "CoAP Observe... This is best-effort -- the server MAY stop notifying at any time." But the spec maps it to the SUBSCRIBE operation, which in other transports provides reliable delivery. No specification of what the client should do when the server stops observing. No re-registration interval. No specification of how to detect that observation has been silently dropped.
- **Why it matters**: A constrained device relying on CoAP Observe for message delivery could silently stop receiving messages with no detection mechanism. The gap between "best-effort observe" and "reliable subscribe" is unacknowledged.
- **Severity**: MEDIUM

---

### [10.10] Free Relay Requirement Has No Enforcement Mechanism

- **Category**: Missing conformance criteria
- **Location**: Section 10.10 (line 337)
- **What's missing**: "Free relays MUST always exist in the bootstrap relay list (section 18.5) -- economic gatekeeping of basic protocol operation is a protocol violation." But: who enforces this? Who maintains the bootstrap relay list? What happens if all free relays go offline? No specification of the fallback when the bootstrap list contains no reachable free relays. No health checking of bootstrap relays.
- **Why it matters**: If the bootstrap free relay list is hardcoded and those relays go down, new users cannot join the network. If the list is dynamic, who updates it? This is a classic bootstrapping problem that the spec identifies but does not solve.
- **Severity**: MEDIUM

---

### [10.5.1] Adapter Tier Fallback Chain Unspecified

- **Category**: Undefined error/failure behavior
- **Location**: Section 10.5.1 (lines 130-155)
- **What's missing**: "Clients SHOULD prefer QUIC over WebSocket when both are available." But no fallback chain beyond this preference. If a relay advertises `["quic", "websocket"]`, the client prefers QUIC. If QUIC fails, does the client try WebSocket? If both fail, does it try the next relay? No retry strategy for transport-level failures. No specification of whether transport fallback is per-relay or per-operation.
- **Why it matters**: Without a specified fallback chain, implementations will differ in resilience. One might retry 3 times on QUIC then fall back to WebSocket; another might immediately fall back. This affects both reliability and latency.
- **Severity**: LOW

---

### [10.9] Presence and Typing Indicators Have No Wire Format

- **Category**: Missing wire format details
- **Location**: Section 10.9 (line 314)
- **What's missing**: "A context that needs presence registers a presence tool. A context that needs typing indicators includes them as ephemeral events." No specification of what an "ephemeral event" is in the context of the event log. Are ephemeral events committed to the Merkle tree? If so, they are permanent (contradicting "ephemeral"). If not, they bypass the event log entirely and need their own delivery mechanism. No specification of TTL for ephemeral events, no wire format, no delivery guarantee.
- **Why it matters**: "Ephemeral events" are mentioned as a mechanism without definition. An implementor has no way to know whether to use MLS application messages, a separate channel, or something else.
- **Severity**: MEDIUM

---

### [10.12.4.1] BRIDGE_REGISTER Routing ID Verification Is Only One-Way

- **Category**: Security-relevant omissions
- **Location**: Section 10.12.4 (line 490)
- **What's missing**: The bridge verifies that the DID maps to the claimed routing_id via `SHA-256("scp:did:" || did_string)`. But this is a DID-to-routing_id derivation, not the context pseudonym derivation in section 9.10.4 (which uses HMAC-SHA256). These are two different derivation functions for routing_id -- the bridge uses `SHA-256("scp:did:" || did_string)` while the context pseudonym system uses `HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")`. Which one does the self-hosted relay actually use for its relay routing?
- **Why it matters**: Two different routing_id derivation schemes are specified in different sections. If the bridge validates using one scheme but the relay publishes using the other, registration will always fail.
- **Severity**: HIGH

---

## Cross-Cutting Concerns

---

### [9/10] No Protocol-Level Maximum Context Size

- **Category**: Missing constants/defaults
- **Location**: Sections 9.16, 9.17, 10.3
- **What's missing**: The spec discusses contexts with 100 members, 1000 members, and "millions of members" (section 9.17.3) but never specifies a maximum. MLS group operations are O(log N) for member removal but O(N) for sender key distribution, CEK wrapping, and access key distribution. No protocol-level guidance on when MLS becomes impractical (groups of 10,000? 100,000?) and broadcast mode should be used instead.
- **Why it matters**: Without size guidance, an implementor might create an MLS group with 100,000 members, where every message includes 100,000 wrapped CEKs (4MB of key material per message). The spec hints at this with "Contexts with >10,000 members SHOULD use batched CEK wrapping" but sets no upper bound.
- **Severity**: MEDIUM

---

### [8/9] No App Sandboxing Within Agent Runtime

- **Category**: Security-relevant omissions
- **Location**: Sections 8.4, 8.5, 9.1
- **What's missing**: The spec says "the attack surface of a badly-generated app is bounded by the declaration contract" (section 8.4) but this is only true if the declaration contract is enforced at the protocol level, not just at the agent presentation layer. The agent has full context access via MLS membership. A compromised or malicious app running within the agent runtime has access to all MLS key material. No sandboxing between apps within the same agent process is specified.
- **Why it matters**: The capability declaration creates a false sense of security if apps can bypass it by accessing the agent's MLS state directly. The "generated apps are safe" claim requires either process isolation or an in-process sandboxing mechanism that the spec does not describe.
- **Severity**: MEDIUM

---

I will now save these findings to memory for future reference.
Here is the complete audit.

---

# SCP Specification Audit: Unspecified Details in Sections 8, 9, and 10

## Summary

This audit covers three spec files: `08-products-and-apps-in-the-graph.md`, `09-security-model.md`, and `10-infrastructure-and-self-hosting.md`. Section 8 is conceptual and intentionally thin -- most gaps there are acceptable at this stage. Section 9 is the core security specification and has the highest density of findings, including one CRITICAL inconsistency (conflicting padding schemes), several HIGH severity security-relevant omissions (publicly derivable pseudonyms, missing context_id binding in key request signatures, clock skew inconsistencies), and numerous missing defaults that leave security mechanisms advisory rather than enforceable. Section 10 has significant gaps in push notification registration, multi-device key management, event log pruning, and NAT coordination protocols.

Total findings: **1 CRITICAL, 16 HIGH, 18 MEDIUM, 5 LOW**.

---

## CRITICAL

### [9.10.3 / 9.10.6] Bucket Size Contradiction
- **Category**: Cross-reference inconsistency
- **Location**: `09-security-model.md` line 540 vs line 608
- **What's missing**: Section 9.10.3 defines message padding bucket sizes as `256B, 1KB, 4KB, 16KB, 64KB, 256KB` (factor-of-4 progression, 6 buckets, max 256KB). Section 9.10.6 defines cover traffic padding buckets as `256, 512, 1024, 2048, 4096 bytes` (power-of-2 progression, 5 buckets, max 4KB). These produce different blob sizes for the same plaintext. A 5KB message pads to 16KB under 9.10.3 but is impossible to fit without chunking under 9.10.6.
- **Why it matters**: Traffic analysis resistance depends on all implementations using identical bucket boundaries. Two implementations following different sections produce distinguishable blobs. This directly defeats the protection both sections exist to provide.
- **Severity**: CRITICAL

---

## HIGH

### [8.4] Capability Declaration Has No Wire Format
- **Category**: Missing wire format details
- **Location**: `08-products-and-apps-in-the-graph.md` line 36
- **What's missing**: The capability declaration is described as "structured, machine-readable" but no schema, no field names, no envelope, no serialization format. The open-questions file says it uses JSON Schema / MCP-compatible resource URIs but no actual schema definition exists.
- **Why it matters**: Two independent implementations cannot produce interoperable capability declarations. This is the "safety boundary for generated apps" with no concrete shape.
- **Severity**: HIGH

### [9.3] Earned Capacity Has No Protocol-Level Defaults
- **Category**: Missing constants/defaults
- **Location**: `09-security-model.md` line 180
- **What's missing**: "New identities start with limited capabilities -- restricted context creation, limited participation slots, constrained tool invocation rates." No initial limits specified. No growth curve. No thresholds. No protocol-level floor.
- **Why it matters**: Without defaults, a fresh deployment has zero Sybil resistance at Layer 1. The spec delegates to "product-layer" but the security model depends on this constraint existing.
- **Severity**: HIGH

### [9.2.1] Tool Interface Rate Limit Defaults Missing
- **Category**: Missing constants/defaults
- **Location**: `09-security-model.md` line 69
- **What's missing**: "Each context enforces rate limits on both inbound and outbound tool calls within a sliding time window." No default rate, no window size, no unit, no behavior on exceeding.
- **Why it matters**: Rate limiting is the primary defense against chained tool call amplification (described in the same section). Without defaults, the defense is advisory.
- **Severity**: HIGH

### [9.9.3] Equivocation Response Undefined
- **Category**: Undefined error/failure behavior
- **Location**: `09-security-model.md` line 481
- **What's missing**: "The context's governance model handles the response." No default response for any governance model. No automatic relay demotion, member alert, or context freeze.
- **Why it matters**: Detection without response is monitoring, not defense. Implementations will vary between "log and ignore" and "halt the context."
- **Severity**: HIGH

### [9.10.3] Message Chunking Algorithm Unspecified
- **Category**: Underspecified algorithms
- **Location**: `09-security-model.md` line 542
- **What's missing**: "Messages larger than 256KB are chunked into 256KB blocks." No chunk header format, no sequence numbering, no reassembly protocol, no lost-chunk handling, no maximum message size.
- **Why it matters**: Chunking requires a wire format for reassembly. Without it, large message support is unimplementable. Individual chunk suppression is cheaper than full message suppression.
- **Severity**: HIGH

### [9.10.4] Pseudonyms Are Publicly Derivable
- **Category**: Security-relevant omission
- **Location**: `09-security-model.md` line 560
- **What's missing**: "For software keys, the HMAC uses the raw Ed25519 public key bytes." The public key is... public. Anyone with the DID and the context_id can compute `HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym")` and derive the pseudonym. The spec claims pseudonyms are "unlinkable across contexts" -- but they are fully linkable if you know the context_id.
- **Why it matters**: A relay operator who knows a context_id can test every known DID against it by computing pseudonyms and checking active subscriptions. Combined with the metadata routing_id (`SHA-256(context_id || "scp-metadata")`) which is also publicly derivable, this enables a membership enumeration oracle.
- **Severity**: HIGH

### [9.10.4] Metadata Routing ID Enables Membership Enumeration
- **Category**: Security-relevant omission
- **Location**: `09-security-model.md` line 561
- **What's missing**: `metadata_routing_id = SHA-256(context_id || "scp-metadata")` is publicly derivable from context_id. Combined with publicly derivable pseudonyms (above), enables enumeration of which DIDs are members of a context.
- **Why it matters**: Any party knowing a context_id can query relays for membership presence. The context_id itself may be guessable or leaked through other protocol interactions.
- **Severity**: HIGH

### [9.16.2] SenderKeyRequest Signature Scope Unspecified
- **Category**: Security-relevant omission
- **Location**: `09-security-model.md` line 794
- **What's missing**: The `SenderKeyRequest` signature scope is not fully specified -- just "verifies the signature." The `SenderKeyEpochAdvance` signature binds `context_id`, but no such binding is specified for SenderKeyRequest. Cross-context replay of key requests could trick a sender into distributing keys to the wrong context.
- **Why it matters**: Without context_id in the signed payload, a request captured in context A can be replayed in context B. This is the exact pattern flagged in my standing memory notes.
- **Severity**: HIGH

### [9.17.1] AccessKeyRequest Replay Window Conflicts with Clock Skew Tolerance
- **Category**: Cross-reference inconsistency
- **Location**: `09-security-model.md` line 921 vs line 731
- **What's missing**: AccessKeyRequest timestamps are rejected after 30 seconds (line 921). General clock skew tolerance is 5 minutes (section 9.14, line 731). Two devices with 35 seconds of clock skew can exchange messages (5-minute tolerance) but cannot exchange access keys (30-second tolerance).
- **Why it matters**: This will cause mysterious access key failures in production. The 30-second window is 10x tighter than the general protocol tolerance.
- **Severity**: HIGH

### [9.17.5] Full Revocation Requires Unspecified Coordinated Key Deletion
- **Category**: Underspecified algorithms
- **Location**: `09-security-model.md` line 983
- **What's missing**: "Delete the target's access key from all members' local stores." No deletion message format. No confirmation protocol. No handling for offline members. No mechanism for the revoker to verify deletion occurred. A single non-compliant client defeats the guarantee.
- **Why it matters**: Coordinated deletion across a distributed system is fundamentally hard. The spec describes it as a simple operation without acknowledging or solving the coordination problem.
- **Severity**: HIGH

### [10.3] Event Log Pruning Explicitly Deferred
- **Category**: Missing constants/defaults
- **Location**: `10-infrastructure-and-self-hosting.md` line 64
- **What's missing**: The spec explicitly states "The protocol must define pruning rules... checkpoint mechanisms... availability requirements..." and then does not define them. No pruning interval, no maximum log size, no checkpoint format.
- **Why it matters**: Without pruning, the event log grows without bound. This is incompatible with the "device-as-node" promise of section 10.2, especially for mobile deployment.
- **Severity**: HIGH

### [10.7] Push Notification Registration Protocol Missing
- **Category**: Missing wire format details
- **Location**: `10-infrastructure-and-self-hosting.md` line 290
- **What's missing**: No specification of how a device registers its push token with a relay. No token format. No authentication of push token registration. No token expiry handling. No association protocol between push tokens and routing_id subscriptions.
- **Why it matters**: Push notifications are the only mobile delivery mechanism. Without a registration protocol, mobile support is unimplementable.
- **Severity**: HIGH

### [10.8] Multi-Device Key Synchronization Dodged
- **Category**: Security-relevant omission
- **Location**: `10-infrastructure-and-self-hosting.md` line 300
- **What's missing**: "Multi-device coordination... is a client-scope concern." But MLS membership is per leaf node (section 9.7.1 maps "agent in context" to one MLS leaf). A user with 3 devices needs either 3 leaf nodes (appearing as 3 members) or shared key material (requiring a sync protocol). Neither is specified.
- **Why it matters**: MLS does not natively support multi-device. Declaring this "client-scope" dodges a fundamental protocol design question that affects member count, encryption cost, and user experience.
- **Severity**: HIGH

### [10.9.1] Media Session Key Derivation Incomplete
- **Category**: Underspecified algorithms
- **Location**: `10-infrastructure-and-self-hosting.md` line 323
- **What's missing**: "MLS derives media session keys (MLS exporter, RFC 9420 section 8)." No exporter label. No exporter context. No key length. No specification of how exported keys integrate with DTLS-SRTP keying.
- **Why it matters**: Without exporter label/context, two implementations derive different media keys for the same group. The MLS-to-WebRTC key binding is the security-critical property and it is completely unspecified.
- **Severity**: HIGH

### [10.12.3] STUN Hole Punching Coordination Protocol Missing
- **Category**: Underspecified algorithms
- **Location**: `10-infrastructure-and-self-hosting.md` line 426
- **What's missing**: "a coordination message through an intermediary relay" -- no wire format for this coordination message. No "intent to connect" signaling protocol. No specification of which intermediary handles coordination.
- **Why it matters**: STUN hole punching for restricted NATs requires mutual packet exchange. Without a coordination protocol, peers behind restricted NATs cannot connect to self-hosted relays behind restricted NATs.
- **Severity**: HIGH

### [10.12.4.1 / 9.10.4] Two Different Routing ID Derivation Schemes
- **Category**: Cross-reference inconsistency
- **Location**: `10-infrastructure-and-self-hosting.md` line 490 vs `09-security-model.md` line 549
- **What's missing**: Bridge registration uses `SHA-256("scp:did:" || did_string)` for routing_id derivation. Context pseudonym system uses `HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")`. These are two different functions that the spec calls "routing_id" in different contexts. No clear specification of which one applies where.
- **Why it matters**: If the bridge validates using one scheme but the relay publishes using the other, bridge registration fails. An implementor reading both sections needs disambiguation.
- **Severity**: HIGH

### [10.14.2] QUIC 0-RTT Replay for PUBLISH
- **Category**: Security-relevant omission
- **Location**: `10-infrastructure-and-self-hosting.md` line 722
- **What's missing**: "SCP operations sent as 0-RTT MUST be idempotent or the relay MUST implement anti-replay measures." PUBLISH is not idempotent. No specification of which operations may use 0-RTT. No specification of the relay's anti-replay mechanism.
- **Why it matters**: If PUBLISH is sent as 0-RTT, a network attacker can replay it, causing duplicate blob storage and duplicate message delivery.
- **Severity**: HIGH

---

## MEDIUM

### [8.4] Capability Declaration Validation Is All-Or-Nothing vs Partial Grant
- **Category**: Ambiguous state transitions
- **Location**: `08-products-and-apps-in-the-graph.md` line 36
- **What's missing**: What happens when an app requests 5 capabilities and 3 are granted? Binary grant/denial vs partial grant is unspecified.
- **Why it matters**: Partial grant without notification could cause app malfunction.
- **Severity**: MEDIUM

### [8.4] Capability Declaration Version Format Missing
- **Category**: Missing constants/defaults
- **Location**: `08-products-and-apps-in-the-graph.md` line 53
- **What's missing**: "Declarations carry a protocol version" -- no version format, no backward compatibility rules, no deprecation mechanism.
- **Why it matters**: Protocol upgrades could silently break apps.
- **Severity**: MEDIUM

### [8.5] MCP Namespace Collision Resolution Unspecified
- **Category**: Missing edge cases
- **Location**: `08-products-and-apps-in-the-graph.md` line 103
- **What's missing**: `context_a/send_message` -- no separator character specified, no collision resolution when two contexts offer the same tool name.
- **Why it matters**: Namespace collision breaks agent tool selection.
- **Severity**: MEDIUM

### [8.5] Agent-Side Capability Filtering Is Not Protocol-Enforced
- **Category**: Security-relevant omission
- **Location**: `08-products-and-apps-in-the-graph.md` line 92
- **What's missing**: Capability filtering is described as MCP presentation-layer only. The agent has full MLS context access regardless of what it exposes via MCP.
- **Why it matters**: The "safety boundary for generated apps" depends on the agent code being trustworthy, not on protocol enforcement.
- **Severity**: MEDIUM

### [9.2] Context Infection Velocity Limits Undefined
- **Category**: Missing constants/defaults
- **Location**: `09-security-model.md` line 29
- **What's missing**: "content bridged N times in M minutes is flagged" -- N and M never defined, "flagged" undefined.
- **Why it matters**: Cited as a mitigation with zero implementation guidance.
- **Severity**: MEDIUM

### [9.2.1] Invitation Rate Limit Defaults Missing
- **Category**: Missing constants/defaults
- **Location**: `09-security-model.md` line 101
- **What's missing**: No per-DID rate, no global rate, no queue depth limit, no priority decay function for the invitation rate limiter.
- **Why it matters**: Human coordination bottleneck defense is advisory without concrete limits.
- **Severity**: MEDIUM

### [9.8.2] Dedup Cache Size Bound Is Ambiguous
- **Category**: Vague requirements
- **Location**: `09-security-model.md` line 378
- **What's missing**: "bounded by a sliding window of the most recent 10,000 envelopes or 24 hours, whichever is larger" -- ambiguous whether this means union semantics (keep both constraints) or max semantics.
- **Why it matters**: An implementation keeping both constraints could consume unbounded memory during burst traffic.
- **Severity**: MEDIUM

### [9.8.5] Reorder Buffer Has No Aggregate Bound
- **Category**: Missing constants/defaults
- **Location**: `09-security-model.md` lines 412-418
- **What's missing**: 100 messages per sender per context, but no aggregate bound across senders or contexts. 1000 senders x 100 messages could exhaust mobile device memory.
- **Why it matters**: Resource exhaustion on constrained devices through legitimate-looking out-of-order delivery.
- **Severity**: MEDIUM

### [9.9.4] MLS Commit Recovery Lacks Timeout
- **Category**: Missing constants/defaults
- **Location**: `09-security-model.md` line 493
- **What's missing**: No timeout for Commit recovery. No retry limit. No fallback to group state reset. No binding to ADR-029's three-tier sync.
- **Why it matters**: A client stuck in a stale epoch could retry indefinitely.
- **Severity**: MEDIUM

### [9.10.4.1] No Maximum Pseudonym Epoch Gap
- **Category**: Missing constants/defaults
- **Location**: `09-security-model.md` line 576
- **What's missing**: No maximum number of pseudonym epochs a client can be behind. A returning client after 50 rotations might need to subscribe to 50 old routing_ids.
- **Why it matters**: Memory and subscription costs scale linearly with missed rotations.
- **Severity**: MEDIUM

### [9.10.6] Cover Traffic Dummy Flag Placement Unspecified
- **Category**: Missing wire format details
- **Location**: `09-security-model.md` line 606
- **What's missing**: `REAL_FLAG = 0x01`, `DUMMY_FLAG = 0x00` -- position in the plaintext not specified. Before padding? After sender-key encryption? Relationship to other envelope fields undefined.
- **Why it matters**: Implementations will disagree on where to check the flag, potentially discarding real messages.
- **Severity**: MEDIUM

### [9.11] Fingerprint Bit Extraction Unspecified
- **Category**: Missing constants/defaults
- **Location**: `09-security-model.md` lines 671-673
- **What's missing**: 128-bit mnemonic: which 128 bits? 200-bit decimal: how is 200 bits encoded into exactly 60 digits? (60 digits encode ~199.3 bits.)
- **Why it matters**: Two implementations using different bit extraction will produce different mnemonics for the same key pair.
- **Severity**: MEDIUM

### [9.12] Compromise Recovery Partial Failure Undefined
- **Category**: Undefined error/failure behavior
- **Location**: `09-security-model.md` line 709
- **What's missing**: No retry limit, no retry backoff, no maximum recovery time, no specification of valid partial-recovery states.
- **Why it matters**: Partial recovery is a real scenario (device offline mid-recovery). The protocol must define safe intermediate states.
- **Severity**: MEDIUM

### [9.14] No Past-Bound on Message Timestamps
- **Category**: Missing edge cases
- **Location**: `09-security-model.md` line 382
- **What's missing**: No absolute past-bound on message age. A message from 30 days ago is accepted if the sender was offline. Interaction with UCAN expiry (24 hours) is unaddressed.
- **Why it matters**: Stale messages authorized by expired UCANs could be delivered and accepted.
- **Severity**: MEDIUM

### [9.15] Destruction Attestation Collection Protocol Missing
- **Category**: Missing conformance criteria
- **Location**: `09-security-model.md` lines 750-768
- **What's missing**: No collection protocol, no quorum requirement, no timeout, no verification mechanism for destruction attestations.
- **Why it matters**: Attestations exist but are never systematically verified.
- **Severity**: MEDIUM

### [9.16.3] Block Notification Uses Inconsistent Serialization
- **Category**: Cross-reference inconsistency
- **Location**: `09-security-model.md` line 815
- **What's missing**: Block notification shown as JSON (`{"type": "block", ...}`). Rest of protocol uses MessagePack. No explicit statement of which format is canonical.
- **Why it matters**: Serialization mismatch causes silent interop failure.
- **Severity**: MEDIUM

### [9.16.7] SDK-Mandated Destruction Timing May Cause DoS
- **Category**: Missing edge cases
- **Location**: `09-security-model.md` line 870
- **What's missing**: Synchronous destruction of cached plaintext blocks all message processing. No timeout. A prolific sender can trigger expensive deletion by blocking.
- **Why it matters**: DoS vector on resource-constrained devices: send 10,000 messages, then block; recipient SDK freezes during synchronous destruction.
- **Severity**: MEDIUM

### [9.17.2] Access Key Generation Authority Ambiguous
- **Category**: Ambiguous state transitions
- **Location**: `09-security-model.md` line 925
- **What's missing**: Who generates the access key -- context creator or AddMember executor? What if AddMember is a governance vote? What if the designated generator is offline?
- **Why it matters**: Access key generation is a single point of failure for new member onboarding.
- **Severity**: MEDIUM

### [9.17.3] member_id Collision in Large Contexts
- **Category**: Missing edge cases
- **Location**: `09-security-model.md` line 951
- **What's missing**: 8-byte truncated DID hash has birthday collision probability ~0.3% at 10M members. No collision resolution mechanism specified.
- **Why it matters**: In broadcast contexts with millions of subscribers, collisions will cause decryption failures.
- **Severity**: MEDIUM

### [10.4] Relay Conformance Tests Miss Operational Behavior
- **Category**: Missing conformance criteria
- **Location**: `10-infrastructure-and-self-hosting.md` line 87
- **What's missing**: `blob_store_conformance!()` and `transport_conformance!()` test happy paths. No conformance tests for rate limiting, connection limiting, abuse prevention, delivery jitter, or bridge behavior.
- **Why it matters**: Two relays passing conformance could behave radically differently under adversarial load.
- **Severity**: MEDIUM

### [10.10] Free Relay Requirement Has No Enforcement
- **Category**: Missing conformance criteria
- **Location**: `10-infrastructure-and-self-hosting.md` line 337
- **What's missing**: "Free relays MUST always exist in the bootstrap relay list." No enforcement mechanism, no health checking, no fallback when all free relays are offline.
- **Why it matters**: Bootstrap failure prevents new users from joining the network.
- **Severity**: MEDIUM

### [10.12.1] NAT Tier Transition Has No Connection Draining
- **Category**: Missing edge cases
- **Location**: `10-infrastructure-and-self-hosting.md` line 379
- **What's missing**: No specification of how to drain connections during tier transition. No overlap period while DID document propagates.
- **Why it matters**: Tier transitions cause message loss during propagation window.
- **Severity**: MEDIUM

### [10.12.4] Bridge Registration Has No Heartbeat or TTL
- **Category**: Missing edge cases
- **Location**: `10-infrastructure-and-self-hosting.md` line 499
- **What's missing**: No keepalive, no TTL, no explicit deregistration for stale registrations. Crashed relay leaves stale routing_id registration.
- **Why it matters**: Stale registrations cause silent message loss -- peers' BRIDGE_DATA succeeds from bridge perspective but messages never reach the crashed relay.
- **Severity**: MEDIUM

### [10.12.4] BRIDGE_REGISTER Replay Within 60-Second Window
- **Category**: Security-relevant omission
- **Location**: `10-infrastructure-and-self-hosting.md` line 491
- **What's missing**: No nonce in BRIDGE_REGISTER. Timestamp-only replay prevention allows 60-second replay window for traffic hijacking.
- **Why it matters**: Captured BRIDGE_REGISTER replayed to a different bridge within 60 seconds redirects traffic.
- **Severity**: MEDIUM

### [10.12.6] ws:// Rejection Boundary Imprecise
- **Category**: Missing conformance criteria
- **Location**: `10-infrastructure-and-self-hosting.md` line 540
- **What's missing**: "MUST reject `ws://` from non-DHT source" -- but no definition of how the SDK tracks the source of a URL. Configuration file? Recommendation from another member? What counts as "non-DHT"?
- **Why it matters**: Imprecise enforcement boundary enables downgrade attacks through edge cases.
- **Severity**: MEDIUM

### [10.9] Ephemeral Events Undefined
- **Category**: Missing wire format details
- **Location**: `10-infrastructure-and-self-hosting.md` line 314
- **What's missing**: "ephemeral events" for presence/typing -- no definition of what an ephemeral event is, whether it enters the Merkle log, TTL, delivery guarantee, or wire format.
- **Why it matters**: Mentioned as a mechanism without any specification.
- **Severity**: MEDIUM

### [10.16.1] Constrained Device Fragment Reassembly Limits Missing
- **Category**: Missing constants/defaults
- **Location**: `10-infrastructure-and-self-hosting.md` line 797
- **What's missing**: No maximum fragment count for DTLS reassembly. A 256KB blob over 1200-byte path MTU needs ~213 datagrams. No reassembly timeout.
- **Why it matters**: Resource exhaustion vector for constrained devices.
- **Severity**: MEDIUM

### [10.16.2] CoAP Observe vs SUBSCRIBE Gap Unacknowledged
- **Category**: Vague requirements
- **Location**: `10-infrastructure-and-self-hosting.md` line 809
- **What's missing**: CoAP Observe is "best-effort" but mapped to SUBSCRIBE which is reliable in other transports. No re-registration interval, no detection of dropped observation.
- **Why it matters**: Silent message loss on constrained devices.
- **Severity**: MEDIUM

### [9/10] No Maximum Context Size
- **Category**: Missing constants/defaults
- **Location**: Sections 9.16, 9.17, 10.3
- **What's missing**: No protocol-level guidance on maximum MLS group size. Wrapped CEKs for 100K members = 4MB per message. No cutoff where broadcast mode should be mandated.
- **Why it matters**: Implementations may create impractically large MLS groups.
- **Severity**: MEDIUM

### [8/9] No App Sandboxing Within Agent Runtime
- **Category**: Security-relevant omission
- **Location**: Sections 8.4, 8.5, 9.1
- **What's missing**: Capability declarations are presentation-layer only. The agent has full MLS key access. No process isolation between apps within the agent runtime.
- **Why it matters**: "Generated apps are safe" claim is false without sandboxing.
- **Severity**: MEDIUM

---

## LOW

### [8.3] App State Portability Has No Pattern
- **Category**: Missing edge cases
- **Location**: `08-products-and-apps-in-the-graph.md` line 23
- **What's missing**: No recommended serialization format, no migration protocol sketch, no app state metadata convention.
- **Why it matters**: Without guidance, every app invents its own migration story.
- **Severity**: LOW

### [9.7.2] Grace Window Condition (a) Is Dead Code
- **Category**: Missing edge cases
- **Location**: `09-security-model.md` line 304
- **What's missing**: Condition (a) "all members have sent at least one message in the new epoch" is unprovable when members are offline. Condition (b) "30 seconds" is the actual bound in all realistic scenarios.
- **Why it matters**: Correctness concern -- condition (a) misleads implementors into tracking an unverifiable property.
- **Severity**: LOW

### [9.9.3] Event Count Tolerance of 5 Is Unjustified
- **Category**: Vague requirements
- **Location**: `09-security-model.md` line 477
- **What's missing**: Why 5 events? Should it scale with context activity? Is 5 a hard constant or a suggestion?
- **Why it matters**: Overly tight for active contexts, overly loose for quiet ones.
- **Severity**: LOW

### [10.13.3] LRU Eviction Does Not Account for Application Activity
- **Category**: Missing edge cases
- **Location**: `10-infrastructure-and-self-hosting.md` line 694
- **What's missing**: LRU based on transport activity, not application activity. A user reading cached messages has their relay connection evicted.
- **Why it matters**: Surprising UX -- connection drops while user is actively reading.
- **Severity**: LOW

### [10.14.3] QUIC Probe Failure Duration Unbounded
- **Category**: Missing constants/defaults
- **Location**: `10-infrastructure-and-self-hosting.md` line 734
- **What's missing**: QUIC fallback lasts "until the next `.well-known/scp` refresh" -- refresh interval unspecified.
- **Why it matters**: A transient network issue could block QUIC indefinitely.
- **Severity**: LOW

---

## Key Files Referenced

- `.docs/specs/08-products-and-apps-in-the-graph.md`
- `.docs/specs/09-security-model.md`
- `.docs/specs/10-infrastructure-and-self-hosting.md`
