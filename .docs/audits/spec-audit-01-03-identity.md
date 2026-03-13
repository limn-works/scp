---

# SCP Specification Gap Audit: Specs 01-03

## Executive Summary

Specs 01 (Thesis), 02 (System Design), and 03 (Identity) serve as the conceptual foundation for SCP. Spec 01 is pure strategy and positioning -- light on protocol-level claims and therefore has few specification gaps, though it makes several claims that downstream specs must substantiate. Spec 02 provides architectural framing through diagrams and narrative but deliberately defers detail, so its gaps are mostly about ensuring cross-reference consistency. Spec 03 (Identity) is where the real problems are. It introduces multiple security-critical subsystems -- key custody, recovery, attestations, identity private state, dual-layer resolution, block/mute -- and leaves several of them either underspecified or specified only at the narrative level without enough detail for a conformant implementation.

The most severe gaps are: (1) the social/device recovery protocol in section 3.3, which is the most important safety mechanism for users and is described in exactly three bullet points with zero wire format, zero quorum rules, and zero failure semantics; (2) identity private state encryption in section 3.7, which says "encrypted to the identity's own keys" without specifying WHICH key, which algorithm, or how multi-device access works; and (3) identity attestation format and verification in section 3.5, which describes the concept thoroughly but provides zero wire format, zero verification protocol, and zero platform-specific bindings.

---

## Findings

### [01-THESIS] "Agents are the primary actors" lacks conformance criteria

- **Category**: Missing conformance criteria
- **Location**: Section 1, line 8 -- "Agents are the primary actors, not humans operating through clients."
- **What's missing**: No conformance test or protocol-level mechanism enforces or distinguishes this property. How does a conformant implementation verify that agents (not humans typing into a UI) are the primary actors? The protocol allows both `#active` and `#agent` signatures (ADR-039), so a human operating through a client is indistinguishable from an agent at the protocol level unless the signing key differs.
- **Why it matters**: This is a thesis statement, not a protocol requirement. If it cannot be tested, it should be explicitly marked as a design philosophy rather than an enforceable property. Currently it reads as a protocol invariant.
- **Severity**: LOW

### [01-THESIS] "Gap between self-hosting and managed infrastructure is negligible" -- no quantification

- **Category**: Vague requirements
- **Location**: Section 1, line 9
- **What's missing**: "Negligible" is never quantified. What operational complexity, cost, or expertise threshold defines negligible? Section 10 covers self-hosting but does not provide a concrete comparison or target metric.
- **Why it matters**: This is a design goal without acceptance criteria. An implementor cannot verify whether their deployment meets this standard.
- **Severity**: LOW

### [01-THESIS] SDK package names are specified without versioning scheme

- **Category**: Missing constants/defaults
- **Location**: Section 1.3, line 35 -- "`pip install scp-python` and `npm install @limn-works/scp-ts`"
- **What's missing**: No versioning scheme is defined for SDK packages. Is it SemVer? CalVer? What constitutes a breaking change at the SDK level vs. the protocol level?
- **Why it matters**: SDK consumers need versioning guarantees. Section 13 (Versioning) addresses protocol evolution but does not specify SDK versioning contracts.
- **Severity**: LOW

### [02-SYSTEM-DESIGN] "One agent per human" rule lacks handling for edge cases

- **Category**: Missing edge cases
- **Location**: Section 2.2, line 75 -- "MEMBERS (one agent per human)"
- **What's missing**: What happens when a user attempts to join a context with a second DID (violating the one-human-per-context rule)? The protocol relies on DID uniqueness, but if a user controls multiple DIDs (which is possible and addressed in section 9.3), the one-agent-per-context invariant is enforceable only per-DID, not per-human. The spec acknowledges this in section 9.3 (Sybil resistance is a deterrent, not enforcement), but section 2.2 presents it as a hard structural property ("one agent per person per context") without the caveat.
- **Why it matters**: An implementor reading only section 2 would believe this is cryptographically enforced. It is not. The inconsistency between sections 2.2 and 9.3 on this point could lead to false security assumptions in implementations.
- **Severity**: MEDIUM

### [02-SYSTEM-DESIGN] Context metadata "Member count" visibility has privacy implications not addressed

- **Category**: Security-relevant omissions
- **Location**: Section 2.2, line 90 -- "Member count" listed as visible metadata
- **What's missing**: Member count is listed as visible metadata (visible before opt-in), but the privacy implications are not discussed here. If a private context's member count is visible to non-members, it leaks information about the context's scale. Section 9.10 (metadata privacy) likely addresses this, but section 2.2 asserts visibility unconditionally.
- **Why it matters**: An implementor reading section 2.2 alone would expose member counts to non-members without considering privacy. The cross-reference to section 9.10 should be explicit.
- **Severity**: MEDIUM

### [02-SYSTEM-DESIGN] Trust function `trust = f(identity, capability, context, metadata)` is undefined

- **Category**: Underspecified algorithms
- **Location**: Section 2.4, line 192
- **What's missing**: The trust function is presented as a formula but never specified. What is `f`? How are the four inputs weighted? What is the output type (boolean, numeric score, enum)? Section 7.5 (Trust Evaluation) clarifies that trust evaluation is agent-level and subjective, but section 2.4 presents it as a protocol formula without qualification.
- **Why it matters**: This creates ambiguity about whether trust evaluation is protocol-specified or implementation-defined. A conformance test cannot verify agent trust decisions if the function is unspecified.
- **Severity**: MEDIUM

### [02-SYSTEM-DESIGN] "Context age" as metadata -- no definition of what constitutes age

- **Category**: Ambiguous state transitions
- **Location**: Section 2.2, line 91
- **What's missing**: "Context age" is listed as visible metadata, but it is undefined. Is it wall-clock time since creation? MLS epoch count? Event log length? What happens if the context creator's clock is wrong?
- **Why it matters**: Implementors need a deterministic definition. If context age is used for trust evaluation (section 9.3 references participation history duration), the measurement must be unambiguous.
- **Severity**: LOW

### [02-SYSTEM-DESIGN] Standing channels "~200ms" context creation claim has no specification basis

- **Category**: Missing conformance criteria
- **Location**: Section 2 references are indirect, but section 9.2 line 88 states "Context creation is a runtime operation (~200ms, section 5.12.4)"
- **What's missing**: The 200ms claim is stated as fact without specifying measurement conditions (hardware, network latency, group size). It appears to be an implementation target, not a protocol requirement.
- **Why it matters**: If implementations target this number, they need to know under what conditions. If it is not a protocol requirement, it should be stated as an implementation note.
- **Severity**: LOW

### [03-IDENTITY] Social and device recovery protocol is almost entirely unspecified

- **Category**: Undefined error/failure behavior
- **Location**: Section 3.3, lines 22-28
- **What's missing**: The entire recovery subsystem is described in three bullet points with zero protocol specification:
  - **Trusted device recovery**: No protocol for how one device "vouches" for another. No wire format for the vouching message. No specification of what "vouching" proves (that the new device holds a key? that the user authenticated on the trusted device?). No maximum number of trusted devices. No timeout for vouching requests.
  - **Social recovery**: No quorum/threshold specification (how many trusted contacts must confirm?). No wire format for recovery requests or confirmations. No protocol for how recovery contacts are designated (stored where? encrypted how?). No specification of what recovery contacts can actually do -- can they issue a new DID? Re-add a member to contexts? Both? Neither? No timeout for social recovery requests. No protection against a colluding subset of recovery contacts.
  - **Platform-backed recovery**: No specification of how platform recovery (Apple/Google) maps to DID key recovery. If the user's iCloud account is recovered, how does that restore their SCP identity key? What if the Secure Enclave key was hardware-bound and cannot be exported?
- **Why it matters**: Recovery is the most important safety mechanism for users. A user who loses their single device and has no recovery path loses their entire identity, all context memberships, and all private state permanently. The spec acknowledges this ("platform-backed recovery is the practical safety net") but provides zero implementation guidance. An implementor cannot build a conformant recovery system from this spec. Section 9.12 covers compromise recovery (key rotation after suspected compromise), but that assumes access to at least one working key. Section 3.3 covers total key loss, and it has nothing.
- **Severity**: CRITICAL

### [03-IDENTITY] Key custody migration "possible without changing identity" -- protocol unspecified

- **Category**: Underspecified algorithms
- **Location**: Section 3.2, line 18 -- "Migration between custody methods is possible without changing identity."
- **What's missing**: No protocol for custody migration. If a user moves from Apple Secure Enclave to a hardware security key, what happens? Is the Identity Key re-generated? If the Identity Key is in a Secure Enclave and cannot be exported, how is migration performed? Does migration require the pre-rotation key? What is the wire format for custody migration authorization?
- **Why it matters**: This is a core claim of the identity layer. If custody migration changes the DID (because the Identity Key changes), then identity continuity is broken. If it does not change the DID, then somehow the same key must move between custody providers -- which is impossible for HSM-bound keys. The spec makes a promise it does not specify how to keep.
- **Severity**: HIGH

### [03-IDENTITY] Identity attestation wire format is unspecified

- **Category**: Missing wire format details
- **Location**: Section 3.5, lines 35-52
- **What's missing**: Section 3.5 describes identity attestations conceptually but provides zero wire format. The attestation envelope in section 7.4.1 provides a high-level structure, but:
  - Field types are not specified (is `id` a UUID? CID? SHA-256 hash?)
  - Serialization format is not specified (JSON? CBOR? MessagePack?)
  - The `evidence` field is "type-specific" but no type-specific evidence schema is defined for identity link attestations
  - The `claim` field is "structured content (type-specific)" but the structure for identity link claims is not defined
  - The `revocation` field specifies "how to check if revoked" but the format of the revocation reference is not defined (URL? DID document entry? Merkle log reference? All three are mentioned but no canonical format is chosen)
  - Signature scope is not defined -- what bytes are signed? The entire serialized attestation minus the signature field? A canonical hash of specific fields?
- **Why it matters**: Two implementations cannot produce interoperable attestations from this spec. An attestation created by one SDK cannot be verified by another unless they agree on serialization, field ordering, and signature scope.
- **Severity**: HIGH

### [03-IDENTITY] Identity attestation verification protocol is unspecified per platform

- **Category**: Underspecified algorithms
- **Location**: Section 3.5, line 44 -- "Verification methods vary by platform (OAuth proof, signed message, DNS record, etc.)"
- **What's missing**: No platform-specific verification protocols are defined. For OAuth: which OAuth flow? What claims must the OAuth token contain? How is the OAuth token bound to the DID? For DNS records: what record type (TXT? CNAME?)? What format? What domain? For signed messages: signed with what key? What format? Where published? The open questions document (line 15) marks this as "Resolved" and says "section 3.5 and section 7.4.2 specify platform-specific verification flows," but they do not -- they list the categories (OAuth, DNS, signed post) without specifying any flow.
- **Why it matters**: Without standardized verification protocols, attestation verification is implementation-specific. Alice's SDK might accept an OAuth token that Bob's SDK rejects because they use different verification criteria. This undermines the "independently verifiable" property (section 3.5, line 44).
- **Severity**: HIGH

### [03-IDENTITY] Attestation revocation check interval undefined

- **Category**: Missing constants/defaults
- **Location**: Section 7.4.4, line 472 -- "agents that cached a previous verification should re-check on a defined interval"
- **What's missing**: The "defined interval" is not defined. How often must a verifier re-check attestation revocation status? Is it per-verification, periodic, or on-use? What is the default interval? What happens if the revocation endpoint is unreachable?
- **Why it matters**: Without a defined interval, implementations will diverge. One SDK might cache attestation validity for 24 hours while another re-checks every 5 minutes. An attacker who revokes a compromised attestation expects it to become invalid within a known window.
- **Severity**: MEDIUM

### [03-IDENTITY] Attestation renewal interval specified only as example

- **Category**: Vague requirements
- **Location**: Section 7.4 references, cross-ref section 7.3.6, line 389 -- "An identity link re-verified via OAuth every 30 days"
- **What's missing**: The 30-day renewal interval is stated as an example ("An identity link re-verified via OAuth every 30 days is more current than one verified once 2 years ago"), not as a protocol requirement. No mandatory renewal intervals are defined for any attestation type. The spec says "the protocol defines standard renewal intervals by attestation type" but does not actually define them.
- **Why it matters**: If renewal intervals are protocol-defined, they need to be specified. If they are implementation-defined, the spec needs to say so explicitly rather than claiming they are protocol-defined.
- **Severity**: MEDIUM

### [03-IDENTITY] Shadow identity claiming (section 3.5 item 2) protocol unspecified

- **Category**: Underspecified algorithms
- **Location**: Section 3.5, line 51 -- "a user can claim it by presenting a matching attestation. The shadow identity merges with their real DID."
- **What's missing**: No merge protocol is specified. What does "merge" mean at the protocol level? Is the shadow DID replaced by the real DID in context membership? Are the shadow's messages re-attributed? What happens to the shadow's participation record? What happens if two users both claim the same shadow identity? What is the authorization flow -- who approves the merge? Section 12 (bridge connectors) is referenced but the merge protocol itself is not specified.
- **Why it matters**: Shadow identity merging has profound implications for identity continuity, participation records, and context membership. Without a specified protocol, implementations will handle merges inconsistently, potentially causing identity confusion or attribute theft.
- **Severity**: HIGH

### [03-IDENTITY] Social graph "relationship strength" computation is undefined

- **Category**: Underspecified algorithms
- **Location**: Section 3.6, line 60 -- "computes relationship strength from shared participation (how many contexts, how long, in what roles)"
- **What's missing**: No algorithm or formula for relationship strength computation. Is this protocol-specified or implementation-defined? If implementation-defined, what are the minimum inputs a conformant implementation must consider?
- **Why it matters**: If relationship strength is used for trust evaluation (section 7.5), implementations need at least a common input set to produce comparable results. Currently two SDKs could compute completely different "relationship strength" values for the same pair of identities.
- **Severity**: LOW (acknowledged as agent-level computation, but should be explicitly stated as such)

### [03-IDENTITY] Graph visibility grant wire format unspecified

- **Category**: Missing wire format details
- **Location**: Section 3.6, lines 62-68
- **What's missing**: Graph visibility grants are described at four granularities (per-identity, per-capability scope, per-context, per-category) but no wire format is specified. How is a grant represented? Where is it stored (identity private state? context state?)? How does an authorized agent query another's social graph -- what is the request/response protocol? What is the capability token format for graph visibility?
- **Why it matters**: Social graph sharing is presented as a core privacy feature, but without a wire format, implementations cannot interoperate on graph visibility.
- **Severity**: MEDIUM

### [03-IDENTITY] Block list propagation timing and failure semantics

- **Category**: Undefined error/failure behavior
- **Location**: Section 3.7.1, lines 158-164
- **What's missing**: Block list propagation is described as "best-effort and idempotent" but several failure scenarios are unaddressed:
  - What if propagation to some contexts succeeds and others fail? Is the global block partially enforced? The spec says "block executes on next connection" for offline contexts, but what about permanently inaccessible contexts?
  - What is the maximum propagation delay? No SLA or upper bound is specified.
  - What if the blocker leaves a context between the global block and propagation to that context? Is the block still propagated?
  - What if the blocked party has already rotated their sender key in a context before the block propagates?
- **Why it matters**: Partial block propagation means the blocked party may still have access to the blocker's content in some contexts while blocked in others. The blocker may have a false sense of security.
- **Severity**: MEDIUM

### [03-IDENTITY] Identity private state encryption algorithm unspecified

- **Category**: Underspecified algorithms
- **Location**: Section 3.7, line 122 -- "Private state is encrypted to the identity's own keys."
- **What's missing**: Which key? The Identity Key (`#0`) is Ed25519, which is a signing key, not an encryption key. The Active Signing Key (`#active`) is also Ed25519. Neither is directly usable for encryption. The MLS ciphersuite uses X25519 for key agreement. So:
  - Is a derived X25519 key used (Ed25519-to-X25519 conversion)?
  - Is a separate encryption key maintained for private state?
  - Which AEAD algorithm is used (AES-128-GCM per the MLS suite? AES-256-GCM? Something else)?
  - How is the symmetric key derived (HKDF? From what input keying material?)
  - What is the nonce/IV generation scheme?
  - What is the AAD (additional authenticated data) for private state encryption?
  - For multi-device access: if the private state is encrypted to "the identity's own keys," and the Identity Key is in a Secure Enclave that cannot export the private key, how does a second device decrypt it? Is there a key wrapping scheme? A derived key shared via some multi-device protocol?
- **Why it matters**: This is the encryption scheme protecting block lists, visibility policies, agent configuration, petnames, and all other personal data. Without a specified algorithm, interoperability is impossible and security is unanalyzable. A reviewer cannot verify that the encryption provides the claimed "same confidentiality guarantee" as context encryption.
- **Severity**: CRITICAL

### [03-IDENTITY] Identity private state event log integrity mechanism underspecified

- **Category**: Underspecified algorithms
- **Location**: Section 3.7, line 130 -- "The event log is authenticated (Merkle root or equivalent)."
- **What's missing**: "Merkle root or equivalent" is not a specification. Which is it? If Merkle tree, is it the same Certificate Transparency structure specified in section 9.5 for context event logs? If "equivalent," what is the equivalent? How is the Merkle root computed for a single-writer log? Where is the root stored? How does a device verify the root on read?
- **Why it matters**: Integrity verification of private state is the defense against relay tampering (explicitly stated: "If a relay tampers with your private state, you detect it on next read"). Without a specified integrity mechanism, this defense does not exist in a conformant implementation.
- **Severity**: HIGH

### [03-IDENTITY] Identity private state size limits unspecified

- **Category**: Missing constants/defaults
- **Location**: Section 3.7, line 136 -- "Less constrained than context state"
- **What's missing**: No size limits are specified for identity private state. The spec says "relays MAY enforce per-DID storage quotas as an operational concern" but provides no default, no recommended range, and no protocol-level maximum. What happens when a relay's storage quota is exceeded? Is the user notified? Are oldest events evicted?
- **Why it matters**: Without a protocol-level size limit or at least a recommended default, relay implementations will diverge. A user who accumulates years of block list events, annotations, and agent memory may find their private state exceeds some relay's arbitrary quota, losing data silently.
- **Severity**: MEDIUM

### [03-IDENTITY] Identity private state conflict resolution for non-commutative operations

- **Category**: Missing edge cases
- **Location**: Section 3.7, line 128 -- "Most identity private state operations are naturally commutative"
- **What's missing**: "Most" implies some are not. Which operations are non-commutative? What happens when non-commutative operations conflict? The spec says "simultaneous updates from multiple devices resolve without conflict in most cases" -- what about the remaining cases? No conflict resolution strategy is specified for the non-commutative exceptions.
- **Why it matters**: If a user updates their notification preferences on their phone and laptop simultaneously with different values, the event log records both. What is the final state? Last-writer-wins? Both retained? The spec does not say.
- **Severity**: MEDIUM

### [03-IDENTITY] Identity private state routing_id derivation unspecified

- **Category**: Missing wire format details
- **Location**: Section 3.7, line 124 -- "Same as context state: encrypted blobs stored on your published relays"
- **What's missing**: Section 3.10.2 specifies DID document routing_id derivation as `SHA-256("scp:did:" || did_string)`. But identity PRIVATE STATE is a different blob type. What routing_id is used for private state blobs? The `IdentityPrivateState` service endpoint (section 3.7 line 139) lists relays, but the actual routing_id for private state blobs is not specified. Is it `SHA-256("scp:identity-private:" || did_string)`? Something else?
- **Why it matters**: Without a specified routing_id, implementations cannot store or retrieve private state from relays interoperably.
- **Severity**: HIGH

### [03-IDENTITY] IdentityPrivateState service endpoint format unspecified

- **Category**: Missing wire format details
- **Location**: Section 3.7, line 139 -- "The DID document includes a service endpoint of type `IdentityPrivateState`"
- **What's missing**: Section 18.2.2 lists `IdentityPrivateState` as a service endpoint type but provides no format specification. Section 18.2.1 specifies the `SCPRelay` format in detail (URL format, multiple entries, ordering). No equivalent specification exists for `IdentityPrivateState`. What is the service endpoint URL format? Is it the same relay URL format as `SCPRelay`? Can it point to different relays than `SCPRelay`? How many entries are recommended?
- **Why it matters**: Implementors cannot construct or parse `IdentityPrivateState` service endpoints without a format specification.
- **Severity**: MEDIUM

### [03-IDENTITY] DID resolution -- stale document "last known sequence number" bootstrap

- **Category**: Missing edge cases
- **Location**: Section 3.10.4, line 274 -- "Verify seq >= last_known_seq for this DID"
- **What's missing**: On first resolution of a DID (no cached document), `last_known_seq` is 0 (or absent). An attacker who can serve a stale document with seq=1 while the current document is at seq=100 wins the first resolution race if their response arrives first. The spec says "accept the valid response with highest sequence number" (line 275), which mitigates this in the parallel query case (both responses compared). But: what if only one layer responds (the other times out)? The single response is accepted regardless of freshness because there is no baseline.
- **Why it matters**: First-contact resolution from a single layer is vulnerable to stale document attacks. The parallel query mitigates but does not eliminate this if one layer is unreachable or compromised.
- **Severity**: MEDIUM

### [03-IDENTITY] DID resolution cancellation of slower query -- no specification

- **Category**: Undefined error/failure behavior
- **Location**: Section 3.10.1, line 209 -- "The slower query is cancelled once the first valid response arrives."
- **What's missing**: No specification of cancellation behavior. What if the slower query has already established a connection? Does it send a cancellation message or just drop the connection? What if the slower query returns a response with a HIGHER sequence number than the first? Should the client actually wait for both before deciding? The text says "first valid response wins" but then section 3.10.7 says "the document with the highest sequence number is accepted" -- these are contradictory if the first response has a lower sequence number.
- **Why it matters**: The contradiction between "first valid response wins" (line 209) and "highest sequence number wins" (line 275) means implementations will diverge. A security-conscious implementation should wait for both; a latency-optimized one should take the first. The spec needs to pick one or specify the reconciliation protocol.
- **Severity**: HIGH

### [03-IDENTITY] DID routing_id collision with context routing_ids

- **Category**: Security-relevant omissions
- **Location**: Section 3.10.2, lines 217-221
- **What's missing**: The domain separator `"scp:did:"` prevents collision with other SCP routing_id schemes. But the spec does not prove or verify non-collision. The context metadata routing_id uses `SHA-256(context_id || "scp-metadata")`. If a context_id happens to start with `"did:"` followed by a DID string, the resulting routing_ids would differ (different prefix structure), but this is not formally proven. More importantly: what prevents a user from creating a context with an ID that, when fed through one routing scheme, produces the same SHA-256 output as a DID through the DID routing scheme? (Answer: SHA-256 collision resistance. But this should be stated explicitly as a security dependency.)
- **Why it matters**: Routing_id collision would cause private state or DID documents to be overwritten by context data or vice versa. The security argument depends on SHA-256 collision resistance, which should be stated explicitly rather than left implicit.
- **Severity**: LOW

### [03-IDENTITY] DID resolution cache invalidation and freshness

- **Category**: Missing constants/defaults
- **Location**: Section 3.10.4, line 276-277 -- "24h refresh for active contacts, 7d for inactive"
- **What's missing**: Definition of "active" vs "inactive" contacts. Is a contact "active" if they share any context? If they exchanged a message in the last N hours? If their DID was resolved in the last M hours? The caching policy values (24h, 7d) are specified but the classification criteria are not.
- **Why it matters**: Without a definition of "active," two implementations may cache the same contact's DID document for dramatically different durations, affecting key rotation propagation time.
- **Severity**: MEDIUM

### [03-IDENTITY] RepublishManager -- relay republish failure handling unspecified

- **Category**: Undefined error/failure behavior
- **Location**: Section 3.10.5, lines 294-296
- **What's missing**: RepublishManager schedules relay republishing every 6 days. What happens if republishing fails? How many retries? What backoff strategy? If a relay is persistently unreachable, is it removed from the publication set? Is the user notified? What if ALL relays are unreachable for more than 7 days (the blob_ttl)? The DID document expires on all relays and the identity becomes unresolvable via the relay layer.
- **Why it matters**: The 7-day TTL with 6-day republish cycle gives a 1-day safety margin. If the device is offline for more than 7 days, the relay-layer DID document expires. The spec should specify recovery behavior for this scenario.
- **Severity**: MEDIUM

### [03-IDENTITY] Bootstrap relay list -- location and update mechanism

- **Category**: Missing constants/defaults
- **Location**: Section 3.10.4, line 270 -- "bootstrap relays from section 18.5.1"
- **What's missing**: Section 18.5.1 is referenced for the fallback relay list, but the actual list of bootstrap relays is not in the spec I was asked to review. The update mechanism for the bootstrap list (how are relays added/removed?) and the minimum set size are not specified in section 3.
- **Why it matters**: If the bootstrap relay list is hardcoded in the SDK and the relays go down, relay-layer resolution fails entirely. The update mechanism is critical for protocol resilience.
- **Severity**: MEDIUM

### [03-IDENTITY] DidResolver trait -- error handling and timeout

- **Category**: Undefined error/failure behavior
- **Location**: Section 3.10.10, lines 342-371
- **What's missing**: The `DidResolver` trait returns `Result<Option<ResolvedDidDocument>, IdentityError>` but:
  - No timeout is specified for the resolve operation. How long should the resolver wait before returning `None`?
  - No specification of what `IdentityError` variants must exist
  - No specification of behavior when the cache returns a document but both layers fail to provide a fresh one -- does it return the cached document with a staleness warning? Return an error? Return the cache silently?
  - The `ResolutionSource::Cache` variant does not record which layer originally served the document or when it was cached
- **Why it matters**: Timeout behavior is critical for user experience (hanging resolution blocks context joining) and for security (a resolver that waits indefinitely for DHT is vulnerable to DoS via DHT unresponsiveness).
- **Severity**: MEDIUM

### [03-IDENTITY] Block/mute -- mute enforcement mechanism underspecified

- **Category**: Underspecified algorithms
- **Location**: Section 3.6, line 93 -- "Muting is a protocol rule enforced in the SDK"
- **What's missing**: "Enforced in the SDK" means what exactly? Does the SDK filter muted content before presenting it to the application? Does it prevent the application from accessing muted content? Or is it a recommendation that apps should check? The spec says "apps built on the SDK inherit this behavior" -- but the enforcement mechanism is unspecified. If the SDK simply does not decrypt muted content, the content is still stored locally. If the SDK decrypts but filters in the presentation layer, the app can bypass the filter.
- **Why it matters**: Mute enforcement at the SDK level has different security properties depending on the implementation. If mute is advisory (the app can override), it is a UX feature, not a protocol rule.
- **Severity**: LOW

### [03-IDENTITY] Tier 1 block -- "forward-only" restoration semantics unclear

- **Category**: Ambiguous state transitions
- **Location**: Section 3.6, line 83 -- "Forward-only -- Dave receives Alice's future content but historical content from before/during the block remains inaccessible (access keys were destroyed, not archived)."
- **What's missing**: What is the precise moment the block takes effect? When the block event is recorded in identity private state? When the sender key rotation completes? When the access key is deleted? These are three different events that may occur at different times. If Dave sends a message between Alice's block event recording and Alice's sender key rotation, does Dave receive it? What about messages from Alice that were in transit (on relays) when the block occurred -- can Dave decrypt them with his old sender key?
- **Why it matters**: The block enforcement window has a race condition between the block event, sender key rotation, and access key deletion. Messages in transit during this window may or may not be accessible depending on implementation timing.
- **Severity**: MEDIUM

### [03-IDENTITY] Bidirectional blocking (Tier 2) -- Dave's SDK behavior unspecified

- **Category**: Underspecified algorithms
- **Location**: Section 3.6, line 85 -- "when Alice blocks Dave, both Alice's and Dave's SDKs rotate their sender keys excluding each other"
- **What's missing**: How does Dave's SDK know to rotate? There must be a protocol message notifying Dave that he has been blocked. What is this message? Is it an MLS application message? A relay-level notification? An identity private state event on Dave's side? The spec says "both SDKs rotate" but the notification mechanism from Alice to Dave is not specified. If Alice blocks Dave and Dave is offline, when does Dave's SDK learn about the block and rotate?
- **Why it matters**: Without a notification mechanism, Dave's SDK cannot know to rotate. This means Alice's side of the block is enforced but Dave's side is not -- leaving a period where Dave can still see Alice's pre-rotation content if he received Alice's old sender key before the block.
- **Severity**: HIGH

### [03-IDENTITY] Per-context block list ProtocolRepository methods missing write operations

- **Category**: Missing wire format details
- **Location**: Section 3.7.1, lines 166-173
- **What's missing**: The ProtocolRepository methods listed are all read operations (get_global_block_list, is_globally_blocked, get_context_block_list, is_blocked_in_context). There are no write operations (add_to_global_block_list, remove_from_global_block_list, add_to_context_block_list, remove_from_context_block_list). The spec says "these methods derive current state from the identity private state event log" but does not specify the write path -- how are BlockDID/UnblockDID events written to the event log?
- **Why it matters**: An implementor needs both read and write interfaces. The write path is the more complex one (it triggers propagation, sender key rotation, access key deletion) and is entirely missing from the ProtocolRepository specification.
- **Severity**: MEDIUM

### [03-IDENTITY] DID document structure for SCP -- field-level specification missing

- **Category**: Missing wire format details
- **Location**: Section 3.7, lines 101-119 (public state tree) and section 18.2 (service endpoints)
- **What's missing**: The spec describes the DID document structure as a tree (verification methods, service endpoints, published attestations) but never provides the complete field-level DID document format. Section 9.7.1 shows the MLS LeafNode credential contains `DID + UCAN + signing_key_id`, but the DID document itself -- which must be serializable for BEP44 signing and publication -- has no canonical field specification. The did:dht spec defines a DNS-based wire format, but SCP's DID document includes SCP-specific extensions (`ScpKeyCustodyAttestation`, multiple SCP service endpoint types, pre-rotation commitments) that must be specified for interoperability.
- **Why it matters**: Two SDKs must produce byte-identical DID documents for the same identity state in order for BEP44 signatures to verify. Without a canonical serialization format, this is impossible.
- **Severity**: HIGH

### [03-IDENTITY] KeyPackage buffer replenishment -- no specification of generation parameters

- **Category**: Missing constants/defaults
- **Location**: Section 9.7.4, line 337 -- "The SDK MUST maintain a buffer of at least 10 unused KeyPackages per identity on relays. Replenished when the buffer drops below 5."
- **What's missing**: KeyPackage generation parameters: what MLS ciphersuite version? What lifetime/expiry for KeyPackages? What credential content (DID, UCAN, signing_key_id -- which UCAN? A dedicated KeyPackage UCAN or the context-scoped one?)? How does the SDK know the buffer has dropped below 5 -- does it poll relays or does the relay push a notification? What if the relay is unreachable during replenishment?
- **Why it matters**: KeyPackage exhaustion means new members cannot be added to contexts involving this identity until KeyPackages are replenished. The replenishment trigger and relay interaction protocol must be specified.
- **Severity**: MEDIUM

### [03-IDENTITY] Linking existing identities (section 3.4) -- entire section is one sentence

- **Category**: Underspecified algorithms
- **Location**: Section 3.4, lines 31-32
- **What's missing**: The entire section is: "Existing platform identities (Google, Apple, social accounts) can be linked to a protocol identity but are never the root. They serve as convenience and interop, not as source of truth." This states the design intent but provides zero specification:
  - How is linking performed at the protocol level?
  - What does "linked" mean? A service endpoint? An attestation? A DID document extension?
  - How is the link verified?
  - Can links be unlinked?
  - How does linking relate to the attestations in section 3.5?
- **Why it matters**: Section 3.4 either duplicates section 3.5 (attestations) or describes something different. If it is attestations, it should cross-reference. If it is something else, it needs specification.
- **Severity**: MEDIUM

### [03-IDENTITY] RepublishConfig::disable_dht() / disable_relay() -- API specified in spec, not in code

- **Category**: Missing conformance criteria
- **Location**: Section 3.10.6, line 307
- **What's missing**: The spec mandates specific API methods (`RepublishConfig::disable_dht()`, `RepublishConfig::disable_relay()`) and a warning message. This is spec-as-API-design, which is unusual and potentially fragile. The conformance requirement should be behavioral ("the SDK MUST warn when a resolution layer is disabled") not API-specific. The mandated warning message text is also specified ("DID resolution layer disabled...") which is overly prescriptive for a protocol spec.
- **Why it matters**: Language bindings may not support the exact Rust API shape. The spec should specify the required behavior, not the Rust API.
- **Severity**: LOW

### [03-IDENTITY] Dual-layer resolution -- no specification for partial failure modes

- **Category**: Undefined error/failure behavior
- **Location**: Section 3.10.4, lines 265-278
- **What's missing**: The resolution protocol describes the happy path (both layers respond, take highest seq). Missing cases:
  - Both layers fail: return cached? return error? How stale can the cache be?
  - One layer returns invalid signature: is this a hard error or does the resolver silently fall back to the other layer?
  - One layer returns valid document, other returns different valid document with SAME sequence number but different content: this should be impossible (same key signs both), but if it happens (implementation bug), what does the resolver do?
  - DHT returns a document but relay returns "not found": does the resolver publish the DHT document to the relay (protocol-level healing mentioned in section 3.10.7 line 315 as "MAY")?
- **Why it matters**: Error handling in resolution directly affects identity availability. Without specified failure modes, implementations will diverge on edge cases that matter most (network partitions, relay outages, DHT unresponsiveness).
- **Severity**: MEDIUM

### [03-IDENTITY] "Earned capacity" system referenced but never specified

- **Category**: Underspecified algorithms
- **Location**: Section 9.3, line 180 (cross-referenced from section 3.5/3.6) -- "New identities start with limited capabilities -- restricted context creation, limited participation slots, constrained tool invocation rates."
- **What's missing**: No specification of initial capacity values, growth rates, or capacity thresholds. What are the default limits for a new identity? How many contexts can a new DID create? How many participation slots? What tool invocation rate? How does capacity grow (linearly? exponentially? step functions?)? What inputs drive growth?
- **Why it matters**: The open questions document marks this as resolved with the note that "earned capacity scoring is a product-layer concern, not a protocol-level specification." But section 9.3 states capacity limits as protocol properties ("restricted context creation, limited participation slots"), not product features. If the protocol does not enforce capacity limits, the Sybil resistance mechanism described in section 9.3 does not work as described. This is a coherence issue between the spec's claims and its explicit deferral.
- **Severity**: HIGH

### [03-IDENTITY] Cross-reference inconsistency: section 3.5 uses did:key in example

- **Category**: Cross-reference inconsistencies
- **Location**: Section 3.5, line 38 -- "The human behind DID `did:key:abc...`"
- **What's missing**: The example uses `did:key` but the protocol's target DID method is `did:dht` (sections 3.8, 9.6.1). `did:key` is not mentioned anywhere else in the spec as a supported method. This is likely an editorial error in the example, but it creates confusion about supported DID methods.
- **Why it matters**: An implementor reading section 3.5 might assume did:key is supported.
- **Severity**: LOW

### [03-IDENTITY] Multi-device access to identity private state -- key sharing protocol absent

- **Category**: Security-relevant omissions
- **Location**: Section 3.7, lines 126-128 -- "Multi-device consistency: two phones and a laptop all append to the same log, all converge to the same state."
- **What's missing**: For multi-device access to work, all devices must be able to decrypt private state. The Identity Key is specified as hardware-bound (Secure Enclave, line 332 of section 9.7.4 -- "Private key never exported from the secure element"). If the Identity Key is used for private state encryption and cannot be exported, a second device cannot decrypt the private state. There must be a key derivation or key sharing protocol for multi-device scenarios. No such protocol is specified.
- **Why it matters**: This is a fundamental architectural gap. Either the private state encryption key must be exportable (contradicting the HSM requirement) or there must be a key distribution protocol between devices. Without either, multi-device private state access is impossible.
- **Severity**: CRITICAL

### [03-IDENTITY] DID document size budget discrepancy

- **Category**: Cross-reference inconsistencies
- **Location**: Section 3.10.2, line 247 -- "DID documents range from 2-30KB... The relay blob size limit is 256KB (ADR-004)."
- **What's missing**: The 2-30KB estimate appears to be based on current assumptions. As the spec adds more service endpoint types (SCPRelay, SCPCapabilities, IdentityPrivateState, PreRotationCommitment, SCPBroadcastContext, ParticipationStatements -- at least 6 types, potentially multiple entries each) plus attestations plus agent capability metadata, this could grow significantly. No maximum size is specified for DID documents specifically, only the general 256KB relay blob limit.
- **Why it matters**: A DID document that approaches the 256KB blob limit would be expensive to resolve and process. The spec should either specify a DID document size limit or acknowledge the growth trajectory.
- **Severity**: LOW

### [02-SYSTEM-DESIGN] Cross-context tool interface "mutual consent" -- governance approval protocol for interfaces not specified in section 2

- **Category**: Vague requirements
- **Location**: Section 2.3, line 125 -- "Both contexts explicitly opt in (mutual consent)"
- **What's missing**: Section 2.3 describes mutual consent for tool interfaces but defers the protocol to section 6.2. The issue is that section 2.3 presents this as a simple property ("both contexts opt in") when the actual protocol requires governance approval, schema validation, and interface registration -- none of which is mentioned in section 2's framing. An implementor reading only section 2 would not understand the complexity.
- **Why it matters**: The section 2 description understates the requirements. This is a specification documentation issue rather than a protocol gap, but it could lead to incomplete implementations.
- **Severity**: LOW

### [03-IDENTITY] Private state event types -- incomplete enumeration

- **Category**: Missing wire format details
- **Location**: Section 3.7.1, lines 146-156
- **What's missing**: Section 3.7.1 defines 4 event types for block lists (BlockDID, UnblockDID, BlockDIDInContext, UnblockDIDInContext). The private state tree (lines 111-119) lists 8 categories of private state (block/mute list, graph visibility policies, agent configuration defaults, personal annotations, petnames, notification preferences, draft attestations, extensible). Only block list events are defined. The remaining 7 categories have no specified event types. How is a graph visibility grant represented as an event? How is a petname assignment represented? How are notification preferences changed?
- **Why it matters**: Without event type definitions for all private state categories, implementations cannot produce interoperable private state event logs.
- **Severity**: HIGH

### [03-IDENTITY] Mute list event types completely absent

- **Category**: Missing wire format details
- **Location**: Section 3.6, line 93 / section 3.7
- **What's missing**: The block list has defined event types (section 3.7.1). The mute list, stored in the same identity private state, has no defined event types. No MuteDID, UnmuteDID, MuteDIDInContext, UnmuteDIDInContext events are specified.
- **Why it matters**: Mute state is portable across devices (stored in identity private state). Without event types, multi-device mute state cannot be synchronized.
- **Severity**: MEDIUM

### [03-IDENTITY] Pre-rotation key storage and custody unspecified

- **Category**: Underspecified algorithms
- **Location**: Section 9.7.4, line 334 -- "Generated at identity creation, stored in cold/offline custody."
- **What's missing**: "Cold/offline custody" is not specified. Is this a paper backup? A hardware security key? A second device? A Shamir secret sharing scheme? The pre-rotation key is the last resort for identity recovery after key compromise (section 9.12). Its custody mechanism determines whether recovery is actually possible. If it is on a piece of paper that the user loses, the entire pre-rotation mechanism fails.
- **Why it matters**: The pre-rotation key is the security backstop for the entire identity system. Its custody must be specified with the same rigor as the Identity Key custody.
- **Severity**: HIGH

### [03-IDENTITY] BEP44 sequence number overflow

- **Category**: Missing edge cases
- **Location**: Section 3.10.7, line 311 -- "The BEP44 sequence number is monotonically increasing"
- **What's missing**: BEP44 sequence numbers are signed 64-bit integers (per BEP44 spec). What happens when the sequence number approaches `i64::MAX`? This is unlikely in practice (trillions of updates) but should be acknowledged. What happens if an implementation uses unsigned 64-bit and a BEP44 node returns a negative sequence number?
- **Why it matters**: Integer overflow in sequence numbers could cause freshness checks to accept stale documents. An explicit note about the sequence number range would prevent implementation bugs.
- **Severity**: LOW

### [03-IDENTITY] Concurrent block and unblock from multiple devices

- **Category**: Missing edge cases
- **Location**: Section 3.7.1, lines 149-151
- **What's missing**: The spec claims block/unblock operations are commutative and conflict-free. But consider: Device A issues `BlockDID { target: Dave, timestamp: T1 }`. Device B, not yet synchronized, issues `UnblockDID { target: Dave, timestamp: T2 }` where T2 > T1. The merged event log contains both events. What is the final state? If events are replayed in timestamp order: blocked at T1, unblocked at T2 -- Dave is unblocked. If replayed in log append order (which may differ from timestamp order due to clock skew): result depends on append order. The spec says operations are commutative, but block/unblock are NOT commutative for the same target -- `block(Dave); unblock(Dave)` is not equal to `unblock(Dave); block(Dave)`.
- **Why it matters**: Block/unblock of the SAME target from different devices is a non-commutative operation. The spec incorrectly claims commutativity. The conflict resolution strategy for same-target block/unblock must be specified (e.g., last-timestamp-wins, or block-always-wins).
- **Severity**: HIGH

---

## Summary Statistics

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 11 |
| MEDIUM | 15 |
| LOW | 9 |
| **Total** | **38** |

## Critical Findings Summary

1. **Section 3.3 -- Social/device recovery protocol unspecified.** The most important user safety mechanism has zero protocol specification. Three bullet points, no wire format, no quorum, no failure semantics.

2. **Section 3.7 -- Identity private state encryption algorithm unspecified.** "Encrypted to the identity's own keys" without specifying which key, which algorithm, key derivation, nonce scheme, or AAD. The claimed confidentiality guarantee is unverifiable.

3. **Section 3.7 -- Multi-device private state access impossible without a key sharing protocol.** The Identity Key is HSM-bound and non-exportable. Private state is encrypted to this key. A second device cannot decrypt it. No key sharing or derivation protocol bridges this gap.

## Structural Observations

The pattern across these three specs is consistent: **conceptual clarity is excellent, protocol specification is sparse.** The spec reads well as a design document -- the abstractions are sound, the security model is thoughtful, the threat analysis in section 9 is thorough. But the gap between "what should happen" and "how it happens at the byte level" is significant in identity-critical areas.

The most dangerous pattern is sections that are marked as "Resolved" in the open questions document but are actually only resolved at the design level, not the protocol level. Social recovery (section 3.3), identity attestation verification (section 3.5), and identity private state encryption (section 3.7) all fall into this category.
