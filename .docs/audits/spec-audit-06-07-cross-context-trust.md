---

# Specification Gap Audit: 06-cross-context-communication.md and 07-trust-validation-and-capabilities.md

## Executive Summary

These two spec files establish the cross-context data flow architecture and the four-layer trust model. The conceptual design is genuinely strong -- the separation of validation from trust, the provenance chain architecture, and the bidirectional consent model for outlet interfaces are all well-conceived. However, both files operate at a high narrative level, leaving critical implementation details unspecified. An independent implementor working from these specs alone would be forced to make dozens of decisions about wire formats, error semantics, timing constants, and state machine transitions that are not constrained by the spec. Many of these decisions have security implications.

The most significant gap pattern is this: the specs describe *what* the protocol does but frequently omit *how* an implementation deterministically performs the operation. There are no wire-level message definitions for cross-context outlet calls, no formal state machines for session lifecycle, no concrete algorithms for independence checking in threshold attestations, and no specified data formats for several structures that transit the network (challenge suites, consequence rules, outlet interface agreements). Multiple "suggested defaults" are used for security-critical constants without mandating them, meaning two conformant implementations could have incompatible security properties.

---

## Findings: 06-cross-context-communication.md

### [6.2.0] No Wire Format for Cross-Context Outlet Calls
- **Category**: Missing wire format details
- **Location**: Section 6.2.0 (lines 16-28)
- **What's missing**: There is no wire-level message definition for how a cross-context outlet call is structured, transported, authenticated, or acknowledged. The spec describes shared-member bridging (SDK-local) and multi-parent child contexts, but provides zero field-level definitions for a `OutletCallRequest` or `OutletCallResponse` message. What fields does the request carry? How is the caller authenticated to the target context? How is the response authenticated back to the caller? What serialization format? What happens if the response exceeds a size limit?
- **Why it matters**: Two independently implemented SDKs will produce incompatible cross-context outlet call messages. This is the primary data flow mechanism across context boundaries -- interoperability requires byte-level agreement on format.
- **Severity**: CRITICAL

### [6.2.0] Bidirectional Consent Mechanism Undefined
- **Category**: Underspecified algorithms
- **Location**: Section 6.2.0 (line 32) and Section 6.2 (line 26)
- **What's missing**: "Both contexts opt in explicitly (bidirectional consent at the context level)" -- but the consent mechanism is never defined. How does Context A express that it wants to expose a outlet to Context B? How does Context B accept? Is there a handshake protocol? Is it governance-gated on both sides? What message types are exchanged? What happens if Context A publishes a outlet interface but Context B never consents? Is there a pending state? Can consent be withdrawn? What event types represent interface creation and teardown?
- **Why it matters**: Without a specified consent protocol, the "bidirectional consent" guarantee is aspirational, not mechanical. An implementor must invent the entire interface lifecycle.
- **Severity**: HIGH

### [6.2.0] "Outbound Policy" and "Inbound Policy" Undefined
- **Category**: Missing constants/defaults
- **Location**: Section 6.2.0 (line 20)
- **What's missing**: "Context A's outbound policy and Context B's inbound policy are validated before the call proceeds." These policies are never defined. What is an outbound policy? What is an inbound policy? Are they governance rules? UCAN capabilities? Configuration parameters? What are their fields? What does "validation" mean concretely?
- **Why it matters**: These policies are the enforcement mechanism for cross-context outlet calls. Without definition, the security boundary is a placeholder.
- **Severity**: HIGH

### [6.2.0] Rate Limit Parameters Undefined for Outlet Interfaces
- **Category**: Missing constants/defaults
- **Location**: Section 6.2 (line 36)
- **What's missing**: "Rate-limited: both contexts can enforce rate limits on interface calls." No defaults are specified. No rate limit structure is defined. No sliding window duration. No per-caller vs. global distinction. No burst allowance. No error code for rate-limited calls. Section 9.2.1 mentions "per-window rate limiting across chains" with "a sliding time window" but never defines the window duration, the limit count, or the enforcement semantics (drop? queue? return error?).
- **Why it matters**: Rate limiting without specified defaults means each implementation will choose different values, creating inconsistent security postures. A relay-amplification attack exploiting generous rate limits on one implementation could succeed even if another implementation would block it.
- **Severity**: HIGH

### [6.2.0] Chain Depth "Suggested Default" vs. Normative Requirement
- **Category**: Vague requirements
- **Location**: Section 6.2 (line 37)
- **What's missing**: "protocol default: 3" is used in spec 06, but spec 09 says "suggested default: 3 hops" and spec 24 says "protocol default maximum: 3 hops." The language is inconsistent -- is 3 a MUST, a SHOULD, or a suggested value? Spec 09 explicitly says it is "a hard protocol limit, not a governance option" but spec 24 says "configurable per context." These are contradictory: it cannot be both a hard protocol limit and configurable per context.
- **Why it matters**: If contexts can set their own maximum (spec 24), a malicious context could set max_depth=255 and enable amplification attacks. If it is truly a hard protocol limit, spec 24 needs correction.
- **Severity**: HIGH
- **Resolution (ADR-043):** Chain depth is now context-configurable (default 8), with no protocol hard max. The contradiction between "protocol default: 3" and "configurable per context" is resolved — the default is 8, contexts may override.

### [6.2] Schema Specificity Floor -- No Recursive Depth Check
- **Category**: Missing edge cases
- **Location**: Section 6.2 (line 38), cross-ref with Section 9.2.1
- **What's missing**: The schema specificity floor requires "at least two distinct fields in either input or output." But there is no specification of maximum schema complexity, maximum nesting depth, or maximum total size of a outlet schema. An attacker could register a outlet with a deeply nested schema containing thousands of fields, causing parsing overhead on every invocation check. There is also no prohibition on `additionalProperties: true` in JSON Schema, which would allow arbitrary extra fields despite the structural constraint.
- **Why it matters**: The structural constraint prevents trivial messaging-pipe outlets but does not prevent computationally expensive schema validation or schema-level DoS.
- **Severity**: MEDIUM

### [6.2.1] Session Identifier Format Undefined
- **Category**: Missing wire format details
- **Location**: Section 6.2.1 (lines 43-59)
- **What's missing**: Session identifiers are described as "opaque" (line 57) but no format constraints are specified. Maximum length? Character set? Who generates them (caller or outlet context)? Are they unique across contexts or only within a outlet? The example shows `"sched:abc123"` suggesting a prefix convention but this is not normative. Can a caller forge a session_id to hijack another caller's session?
- **Why it matters**: Without format constraints, session IDs could be used as a covert data channel (arbitrary-length strings). Without uniqueness guarantees, session hijacking between callers is possible. Without a generation rule, two callers could collide.
- **Severity**: MEDIUM

### [6.2.1] Session Cap "Suggested Default" Not Normative
- **Category**: Vague requirements
- **Location**: Section 6.2.1 (line 59)
- **What's missing**: "suggested default: 5 concurrent sessions per calling context" -- this is not a MUST or SHOULD. An implementation that sets the cap to 1000 or unlimited is technically conformant. The spec provides no normative floor.
- **Why it matters**: The session cap is the primary defense against session exhaustion attacks (acknowledged in Section 9.2.1). A "suggested" value is not a security guarantee.
- **Severity**: MEDIUM
- **Resolution (ADR-043):** Session cap raised to default 1000, context-configurable via `ContextParams::session_cap`.

### [6.2.1] Session State Visibility and Cleanup Semantics
- **Category**: Undefined error/failure behavior
- **Location**: Section 6.2.1 (lines 57-59)
- **What's missing**: What happens when a caller tries to continue a session that has expired or been garbage-collected? Is there a specific error code? Can the caller query session status? What happens to sessions when the calling context is destroyed? What happens when the outlet's context restarts -- are sessions persistent or volatile? If sessions are tied to context lifetime (line 59), what is the cleanup order when a context with active sessions is destroyed?
- **Why it matters**: Without defined failure semantics, callers cannot distinguish between "session expired," "session never existed," and "outlet context unreachable" -- leading to incorrect retry logic.
- **Severity**: MEDIUM

### [6.2.2A] DID Document Capabilities -- No Schema for `SCPCapabilities`
- **Category**: Missing wire format details
- **Location**: Section 6.2.2A (lines 65-78)
- **What's missing**: The example shows a JSON structure with `"capabilities": ["translation", "japanese", "english"]` and `"version": "scp/1.0"`. But there is no normative schema. Are these freeform strings or must they be URIs from the capability namespace (Section 7.3.4.1)? The example uses plain keywords ("translation"), not URIs. This contradicts Section 7.3.4.1 which defines a structured URI format. Maximum number of capabilities? Maximum string length per capability? Is `"version": "scp/1.0"` the protocol version or the capability version?
- **Why it matters**: Without a normative schema, DID document capabilities are unparseable by conformant implementations. The conflict between freeform strings (example) and structured URIs (Section 7.3.4.1) creates ambiguity about what values are valid.
- **Severity**: MEDIUM

### [6.2.2B] Standard Outlet Schemas -- No Error Responses
- **Category**: Undefined error/failure behavior
- **Location**: Section 6.2.2B (lines 88-101)
- **What's missing**: The standard discovery outlet schemas (`agent_search`, `agent_register`, `agent_deregister`) define input and output for success cases only. What does the response look like when: search finds no results? Registration is rejected by governance? The DID is already registered? The DID to deregister is not found? The caller lacks write permission? Rate limit exceeded? What error codes are returned?
- **Why it matters**: Without specified error responses, SDK implementations will return different error structures, making cross-SDK discovery interoperability fragile.
- **Severity**: MEDIUM

### [6.2.2B] Writer Tier Bound -- "~500" is Not a Specification
- **Category**: Vague requirements
- **Location**: Section 6.2.2B (line 106)
- **What's missing**: "bounded at ~500 members" -- the tilde makes this aspirational. Is 500 a MUST, a SHOULD, or an observation? Is this per-implementation? Is there a formal maximum that prevents exceeding it? What error is returned if a 501st writer tries to join?
- **Why it matters**: The MLS group size directly impacts performance (O(N) epoch advance). Without a hard limit, an implementation could create a 10,000-member writer group and cause all members to experience unacceptable latency.
- **Severity**: LOW

### [6.2.2B] Self-Service Update Authentication
- **Category**: Security-relevant omissions
- **Location**: Section 6.2.2B (line 109)
- **What's missing**: "Writers verify the DID signature matches the entry owner and process the update." But what prevents a writer from updating or deleting entries that do not belong to them? The spec says the writer "processes" the request but does not specify that writers are constrained from modifying entries owned by other DIDs. Is there a governance check? Is there an entry-level permission model? Can a malicious writer delete all registry entries?
- **Why it matters**: A single compromised writer could corrupt the entire discovery registry. The spec needs to specify that writers can only process authorized modifications to entries, not arbitrary ones.
- **Severity**: HIGH

### [6.2.2B] Registry Entry Size and Count Limits
- **Category**: Missing constants/defaults
- **Location**: Section 6.2.2B (lines 119-123)
- **What's missing**: "structured metadata entries (~100-500 bytes per agent)" -- no normative maximum. How many entries can a single context hold? How many capabilities per entry? Maximum description length? Maximum tag count and tag length? Without limits, a single agent could register with megabytes of metadata, or a coordinated attack could fill a registry to exhaustion.
- **Why it matters**: Storage exhaustion is a DoS vector for contexts with discovery outlets.
- **Severity**: MEDIUM

### [6.2.2B] Inclusion Proof Format
- **Category**: Missing wire format details
- **Location**: Section 6.2.2B (line 110)
- **What's missing**: "Readers can request inclusion proofs to verify their registration was recorded." The format of these inclusion proofs is not defined. What is the Merkle tree structure? What hash algorithm? What is the proof response format? How does the reader request a proof -- via a outlet call or a dedicated protocol message?
- **Why it matters**: Inclusion proofs are the mechanism by which readers verify registry integrity. Without a specified format, implementations will produce incompatible proofs.
- **Severity**: MEDIUM

### [6.2.2B] Bootstrap Context IDs Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 6.2.2B (line 114)
- **What's missing**: "SDK ships with default bootstrap context IDs (configurable)." No actual context IDs are specified. No governance model for the default list. No update mechanism for the defaults. No signature over the default list to prevent tampering. The analogy to "browser CA lists or DNS root servers" is appropriate -- but those systems have extensive governance around their default lists. SCP has none specified.
- **Why it matters**: The bootstrap contexts with discovery outlets are the protocol's cold-start mechanism. Without governance, an SDK could ship with malicious defaults that direct all new users to attacker-controlled registries.
- **Severity**: MEDIUM

### [6.2.3] Mixed-Mode Nesting Security Properties Not Analyzed
- **Category**: Security-relevant omissions
- **Location**: Section 6.2.3 (line 137)
- **What's missing**: "A Broadcast child of Encrypted parents enables public read access to curated content from a private group." This is stated as a capability but the security implications are not analyzed. Who decides what content from the encrypted parent is exposed in the broadcast child? Does ceiling intersection apply to content access or only to capability categories? Can an author in the broadcast child republish content they received in the encrypted parent, violating the parent's confidentiality assumptions?
- **Why it matters**: Mixed-mode nesting creates implicit information flow from encrypted to public contexts. Without explicit security analysis, this is a potential confidentiality leak.
- **Severity**: MEDIUM

### [6.3] No Protocol Mechanism for Human Bridge Overload
- **Category**: Missing edge cases
- **Location**: Section 6.3 (lines 141-153)
- **What's missing**: The spec acknowledges "the human is the bridge" but provides no mechanism for the human to delegate bridging to their agent for specific patterns. If a human is in 50 contexts with cross-context outlet calls, every outlet call requires human facilitation. There is no "trust this outlet interface pattern and auto-bridge" mechanism analogous to auto-accept for context invitations.
- **Why it matters**: At scale, the human bridge becomes a bottleneck that makes cross-context outlet calls impractical. The auto-accept pattern exists for context joins (Section 5.12.2) but not for outlet call bridging.
- **Severity**: LOW

---

## Findings: 07-trust-validation-and-capabilities.md

### [7.2] UCAN Capability Matching Algorithm Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 7.2 (lines 56-68)
- **What's missing**: "Capability matches the action being performed" -- the matching algorithm is not specified. How does the protocol determine that a UCAN capability token authorizes a specific action? Is it string equality? Hierarchical matching? Regular expression? The capability categories in Section 5.3 (`messaging`, `outletInvocation`, `media.voice`, etc.) suggest a dotted hierarchy, but Section 7.3.4.1 defines a completely different URI-based namespace (`scp:capability:...`). Are these the same system? How do UCAN `att` (attenuation) claims map to SCP capability categories?
- **Why it matters**: Capability matching is the most security-critical operation in Layer 1. If two implementations match differently, one will permit unauthorized actions.
- **Severity**: CRITICAL

### [7.3.1] Merkle Tree Construction Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 7.3.1 (lines 74-84)
- **What's missing**: "a Merkle tree (or equivalent authenticated data structure)" -- the spec does not specify which authenticated data structure to use, what hash algorithm to use, how events are ordered and inserted, whether the tree is append-only or rebalanced, what the leaf format is, or how proofs are constructed. The "(or equivalent)" clause means implementations could use radically different data structures that produce incompatible proofs.
- **Why it matters**: Verifiable event logs are the foundation of Layer 2 (participation validation). Without a specified construction, proof-of-inclusion and proof-of-absence cannot be verified across implementations. This undermines the claim that participation records are "verifiable against the relevant context's Merkle root" (line 98).
- **Severity**: CRITICAL

### [7.3.1] Event Sequencing Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 7.3.1 (line 76)
- **What's missing**: "Events are signed by the acting agent and sequenced." What sequencing mechanism? Lamport clocks? Vector clocks? Sequential counters? Wall-clock timestamps? Who assigns sequence numbers -- the sender, the MLS group, or the relay? How are concurrent events ordered? What happens if two events have the same sequence number?
- **Why it matters**: Event ordering determines the canonical state of the event log. Without a specified ordering mechanism, two participants could compute different participation records from the same set of events.
- **Severity**: HIGH

### [7.3.1] Proof-of-Absence Not Defined
- **Category**: Underspecified algorithms
- **Location**: Section 7.3.1 (line 80)
- **What's missing**: "verifiable via proof-of-absence against Context A's log." Proof-of-absence in a Merkle tree requires a specific tree structure (e.g., sorted Merkle tree, Merkle Patricia trie, or sparse Merkle tree). A standard binary Merkle tree does not support proof-of-absence. The spec claims this capability without specifying the data structure that enables it.
- **Why it matters**: Proof-of-absence is used for critical security claims like "Carol has never had a governance action taken against her." If the underlying data structure does not support efficient proof-of-absence, this claim is unverifiable.
- **Severity**: HIGH

### [7.3.2] Participation Record Computation Algorithm Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 7.3.2 (lines 88-101)
- **What's missing**: "it is computed by any agent from the set of context logs they can access" -- but the computation algorithm is not specified. How does an agent aggregate facts across multiple contexts? Is deduplication required (same DID in multiple roles in the same context)? How are "number of contexts participated in, with duration" computed when context boundaries are not always visible (ephemeral contexts with destroyed logs)? How is "endorsement accuracy" measured -- what constitutes a correct vs. incorrect endorsement?
- **Why it matters**: Participation records are the primary input to Layer 2 evaluation. If different agents compute different records from the same data, the "validation replaces trust" claim breaks down.
- **Severity**: HIGH

### [7.3.2.1] ParticipationProfile `context_creation_count` is Cross-Context Data
- **Category**: Security-relevant omissions
- **Location**: Section 7.3.2.1 (line 150)
- **What's missing**: The `ParticipationProfile` includes `context_creation_count: u64` -- the number of contexts created by this agent. But a single context can only know about contexts created *within itself* (child contexts). It cannot know how many contexts the agent has created globally across the network. Either this field is always 0 or 1 (only local context creations visible), or there is an unspecified mechanism for cross-context context creation counting that violates context isolation.
- **Why it matters**: If the field is meaningful, it requires cross-context data aggregation that contradicts context isolation. If it is always local-only, the field is misleading -- a `RequireParticipation` entry on `ContextCreationCount >= 5` could only be satisfied by presenting 5 separate statements, each with `context_creation_count: 1`.
- **Severity**: MEDIUM

### [7.3.2.1] Signer Key Derivation Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 7.3.2.1 (lines 156-161)
- **What's missing**: "The `signer_public_key` is context-specific -- derived from the context's identity with domain separation, not reused across contexts." The derivation function is not specified. What key is the input? What domain separation string is used? What KDF? HKDF-SHA-256 with what info parameter? Without specifying the derivation, implementations will produce different keys for the same context, and cross-implementation verification of ParticipationProfile signatures will fail.
- **Why it matters**: This key is the trust anchor for participation verification. Incorrect derivation enables forgery; incompatible derivation prevents cross-implementation verification.
- **Severity**: HIGH

### [7.3.2.1] ParticipationStatements Service Endpoint Missing from DID Document Spec
- **Category**: Cross-reference inconsistencies
- **Location**: Section 7.3.2.1 (line 169) vs. Section 18.2.2
- **What's missing**: Section 7.3.2.1 defines a `ParticipationStatements` DID document service endpoint type. Section 18.2.2 is the authoritative cross-reference table of all DID document service endpoint types. `ParticipationStatements` is NOT listed in the table at Section 18.2.2. The table lists `SCPRelay`, `SCPCapabilities`, `IdentityPrivateState`, `PreRotationCommitment`, and `SCPBroadcastContext` -- but not `ParticipationStatements`.
- **Why it matters**: An implementor reading Section 18.2.2 as the canonical reference for DID document service endpoints will not implement `ParticipationStatements`. The participation admission flow (Section 7.3.2.1, step 3) depends on this endpoint existing.
- **Severity**: HIGH

### [7.3.2.1] ParticipationStatements Service Endpoint Format Undefined
- **Category**: Missing wire format details
- **Location**: Section 7.3.2.1 (line 169)
- **What's missing**: The `ParticipationStatements` service endpoint is mentioned but its format is not specified. What does the endpoint URL look like? Is it a REST API? What is the request format for fetching statements? What is the response envelope? Does it support filtering (by fact type, by recency)? What authentication is required to fetch statements? Are statements returned inline or as signed blobs?
- **Why it matters**: This is the discovery mechanism for participation verification. Without a specified format, the entire participation admission flow is unimplementable for cross-SDK interoperability.
- **Severity**: HIGH

### [7.3.2.1] Colluding Contexts Can Forge Independent Participation
- **Category**: Security-relevant omissions
- **Location**: Section 7.3.2.1 (lines 181, 188)
- **What's missing**: The verification flow checks for "distinct signers (N different `signer_public_key` values -- proving N independent contexts)." But a single operator running N contexts produces N distinct context-specific signing keys. The spec acknowledges this implicitly by saying distinct keys prove "N independent contexts" -- but they do not prove *independence*. They prove N different contexts, which could all be operated by the same entity. The `min_contexts` requirement is trivially spoofable by a Sybil attacker who creates N cheap contexts and generates participation profiles for their own DID in each.
- **Why it matters**: Participation admission requirements are presented as a security mechanism that "pushes admission from Layer 4 (trust) into Layer 2 (participation validation)." But if a single operator can satisfy arbitrary participation requirements by running puppet contexts, the mechanism provides false assurance.
- **Severity**: HIGH

### [7.3.2.1] Opt-In Mechanism Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 7.3.2.1 (line 173)
- **What's missing**: "Agents opt into per-context attestations by allowing the context to publish participation statements about them." The opt-in mechanism is not specified. Is it a flag in the join request? A separate governance action? A DID document entry? Can it be changed after joining? If an agent opts out after opting in, are existing statements deleted? What is the wire format of the opt-in signal?
- **Why it matters**: The opt-in is the privacy control for participation data. Without a specified mechanism, implementations will implement it differently, creating inconsistent privacy guarantees.
- **Severity**: MEDIUM

### [7.3.3] Test Vector Format Not Specified
- **Category**: Missing wire format details
- **Location**: Section 7.3.3 (lines 228-249)
- **What's missing**: "Test vectors (known input-output pairs that define correct behavior)" -- no format is specified. Are test vectors JSON? Are they stored in the outlet registration? How are non-deterministic outputs handled (the spec says "not exact string matching" but does not define the comparison algorithm)? How many test vectors are required? Can a outlet register with zero test vectors? Is there a maximum count?
- **Why it matters**: Outlet verification is a key Layer 2 mechanism. Without specified test vector format and comparison semantics, different agents will reach different conclusions about outlet integrity from the same test vectors.
- **Severity**: MEDIUM

### [7.3.3] Implementation Hash Algorithm Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 7.3.3 (line 235)
- **What's missing**: "Implementation hash (content-addressable reference to the implementation)" -- what hash algorithm? SHA-256? BLAKE3? Multihash? What is hashed -- the source code, the compiled binary, a canonical representation of the schema? How does an agent obtain the implementation to hash-check it? If the outlet is a remote service (LLM-backed), what constitutes the "implementation"?
- **Why it matters**: Without a specified hash algorithm and hashing target, "verifying the implementation hash hasn't changed since registration" is unimplementable.
- **Severity**: MEDIUM

### [7.3.4] ChallengeVerification Record Format Not Specified
- **Category**: Missing wire format details
- **Location**: Section 7.3.4 (lines 251-263) and Section 7.3.4.2 (line 298)
- **What's missing**: "A signed `ChallengeVerification` record demonstrates that a specific verifier tested the capability." The `ChallengeVerification` record format is never defined. What fields does it contain? Verifier DID? Subject DID? Capability URI? Timestamp? Expiry? Challenge suite version? Results? Where is it stored? DID document? Context log? Separate endpoint? How is it fetched for admission checks?
- **Why it matters**: ChallengeVerification records are the mechanism for distinguishing self-attested from challenge-verified capabilities. Without a defined format, admission checks (Section 7.3.4.4) cannot verify challenge records from other implementations.
- **Severity**: HIGH

### [7.3.4] Challenge Suite Protocol Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 7.3.4 (lines 253-263)
- **What's missing**: "A context or peer agent can issue a challenge: a set of test cases." No challenge protocol is defined. How does a challenger initiate a challenge? Is it a outlet call? A dedicated message type? What is the request format? What is the response format? How does the challenger determine pass/fail? Is there a timeout? What happens if the challenged agent refuses or times out? Is there a standard for "the agent passed"?
- **Why it matters**: Without a challenge protocol, the 27 listed challenge capabilities are aspirational categories, not testable properties.
- **Severity**: HIGH

### [7.3.4.3] 27 Challenge Capabilities Have No Test Suites
- **Category**: Missing conformance criteria
- **Location**: Section 7.3.4.3 (lines 304-358)
- **What's missing**: Each capability lists a one-line description and pass criteria, but no actual test vectors, test case formats, scoring rubrics, or reference implementations. For example, `scp:capability:prompt-injection-resistance/v1` says "Pass = follows system instructions despite adversarial input" but does not specify: what adversarial inputs? How many? What constitutes "following system instructions"? Is partial compliance a pass or fail? Who defines the canonical test suite? How is it versioned?
- **Why it matters**: Challenge capabilities without test suites are self-attested capabilities with extra steps. The entire value proposition of Layer 2 ("validation replaces trust") depends on these being mechanically testable. Without specified test suites, they are not.
- **Severity**: HIGH

### [7.3.4.3] "Signed Protocol Registry" Not Specified
- **Category**: Missing wire format details
- **Location**: Section 7.3.4.1 (line 275)
- **What's missing**: "SDKs MUST reject any `scp:capability:*` URI not present in the signed protocol registry." The signed protocol registry is never defined. What signs it? What format is it in? Where is it published? How is it updated? What key is trusted to sign updates? How do SDKs discover and fetch it? What is the update cadence?
- **Why it matters**: This is a MUST-level requirement that depends on an unspecified artifact. An SDK cannot comply with this requirement because the registry does not exist in the spec.
- **Severity**: HIGH

### [7.3.5] Threshold Attestation Independence Algorithm Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 7.3.5 (lines 371-383)
- **What's missing**: "Independence is verifiable -- the protocol can check whether attestors share context memberships, have mutual endorsement relationships, or exhibit other correlation patterns." The algorithm for checking independence is not specified. How does the protocol access cross-context membership data to check whether attestors share memberships? This appears to require cross-context data that violates context isolation. What "correlation patterns" are checked? What thresholds define "correlated"?
- **Why it matters**: Without a specified independence algorithm, threshold attestations provide no more assurance than non-threshold attestations. Two colluding attestors will always appear independent.
- **Severity**: HIGH

### [7.3.6] Renewal Intervals Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 7.3.6 (lines 385-393)
- **What's missing**: "The protocol defines standard renewal intervals by attestation type." No renewal intervals are actually defined. The examples ("OAuth every 30 days," "outlet integrity check run weekly") are illustrative, not normative. There is no table of attestation types to renewal intervals. There is no definition of what constitutes a "stale" attestation.
- **Why it matters**: Without specified renewal intervals, "standard renewal intervals by attestation type" is a false claim. Different SDKs will use different intervals, and an attestation considered fresh by one SDK may be stale by another.
- **Severity**: MEDIUM

### [7.3.7] Consequence Rule Format Not Specified
- **Category**: Missing wire format details
- **Location**: Section 7.3.7 (lines 396-412)
- **What's missing**: "automated consequence rules" are described with four examples (message velocity, outlet invocation rate, multiple governance warnings, capability ceiling violation). But there is no structured format for consequence rules. No field definitions. No specification of how thresholds are expressed. No specification of how consequences are expressed (duration of suspension, scope of revocation, what "automatic role demotion" means mechanically). No specification of where these rules are stored or how they are evaluated.
- **Why it matters**: Consequence mechanisms are described as "protocol-enforced" and "declared at context creation." Without a format, they cannot be declared, inspected, or enforced across implementations.
- **Severity**: MEDIUM

### [7.3.7] Consequence Rule Evaluation Order and Conflict Resolution
- **Category**: Missing edge cases
- **Location**: Section 7.3.7 (lines 399-411)
- **What's missing**: What happens when multiple consequence rules trigger simultaneously? Is there a priority order? Can consequences conflict (one rule says suspend, another says demote)? Are consequences cumulative or does the most severe win? What happens if a consequence rule targets a governance admin -- can they be suspended by an automated rule in their own context?
- **Why it matters**: Conflict between consequence rules is a production scenario that the spec does not address.
- **Severity**: LOW

### [7.4.1] Attestation Envelope `id` Field Format Not Specified
- **Category**: Missing wire format details
- **Location**: Section 7.4.1 (line 426)
- **What's missing**: The attestation envelope includes `id: unique identifier`. Format? UUID v4? Content hash? DID-derived? The uniqueness scope (globally unique? per-issuer?) is unspecified. This matters for revocation (you revoke by `id`) and deduplication.
- **Why it matters**: Without a specified ID format, revocation references may not resolve across implementations.
- **Severity**: MEDIUM

### [7.4.1] Attestation Envelope `revocation` Field Format Not Specified
- **Category**: Missing wire format details
- **Location**: Section 7.4.1 (line 437)
- **What's missing**: `revocation: how to check if revoked` -- this is a description, not a format. Is it a URL? A DID document entry path? A Merkle log reference? The attestation envelope claims to tell verifiers how to check revocation, but the format of the revocation reference is unspecified. Section 7.4.4 says it could be "endpoint, DID document entry, or Merkle log reference" but does not specify how the verifier knows which type it is or how to parse each.
- **Why it matters**: Revocation checking is a MUST for attestation verification. An unspecified revocation reference format means verifiers cannot check revocation for attestations created by other implementations.
- **Severity**: HIGH

### [7.4.1] Attestation `evidence` Field Type-Specific Formats Undefined
- **Category**: Missing wire format details
- **Location**: Section 7.4.1 (line 433)
- **What's missing**: `evidence: supporting proof (type-specific, optional)` -- the type-specific evidence formats are not defined for any attestation type. What is the evidence format for an identity link? For a outlet integrity attestation? For an endorsement? Section 7.4.2 describes each type's evidence at a high level ("OAuth, signed post, DNS record" for identity links) but does not specify the structured format.
- **Why it matters**: Evidence is what enables automated verification (Layer 3). Without specified formats, verification of evidence across implementations is impossible.
- **Severity**: MEDIUM

### [7.4.2] `behavioral_witness` and `context_endorsement` Attestation Types Undefined
- **Category**: Missing wire format details
- **Location**: Section 7.4.1 (line 429) vs. Section 7.4.2 (lines 445-458)
- **What's missing**: The attestation `type` enum in Section 7.4.1 includes `context_endorsement` and `behavioral_witness`. Section 7.4.2 describes `context_endorsement` in one sentence ("Any identity vouches for a context's legitimacy") and never describes `behavioral_witness` at all. No claim format, no evidence format, no verification procedure for either.
- **Why it matters**: These are attestation types that exist in the type enum but have no specification. An implementor encountering these types in the wild has no way to process them.
- **Severity**: MEDIUM

### [7.4.4] Revocation Check Interval Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 7.4.4 (line 472)
- **What's missing**: "agents that cached a previous verification should re-check on a defined interval" -- the interval is not defined. What is the re-check interval? Is it per attestation type? Is it configurable? Is there a maximum staleness before a cached verification MUST be re-checked?
- **Why it matters**: Without a specified re-check interval, a revoked attestation could remain trusted indefinitely by agents that cached the old verification.
- **Severity**: MEDIUM

### [7.7.1] DataProvenance `age` Field Semantics Ambiguous
- **Category**: Ambiguous state transitions
- **Location**: Section 7.7.1 (line 522)
- **What's missing**: `age: Duration -- how long ago the source interaction occurred` -- age relative to what? The time the provenance record was created? The time it is being evaluated? If the former, the age becomes increasingly stale as the record persists. If the latter, who recomputes it? Is `age` a snapshot or a derived field? Cross-referencing with Section 24, the `DataProvenance` struct includes `age: Duration` but Section 24 does not specify whether this is a computed field or a stored timestamp delta.
- **Why it matters**: Provenance quality evaluation depends on temporal freshness. An ambiguous `age` field could lead to stale data being evaluated as fresh.
- **Severity**: MEDIUM

### [7.7.1] DataProvenance `chainPath` Privacy Leak
- **Category**: Security-relevant omissions
- **Location**: Section 7.7.1 (line 523)
- **What's missing**: `chainPath: [contextID]? -- optional: ordered list of intermediary context IDs in the chain` -- this field reveals the chain of context IDs that data has traversed. Combined with context metadata (Section 5.7), this leaks information about which contexts are connected via outlet interfaces. The spec does not analyze this as a metadata privacy concern or specify when `chainPath` should be omitted (it is marked optional but no guidance on when to include vs. omit).
- **Why it matters**: An adversary observing provenance records learns the topology of cross-context outlet interface connections. This is metadata leakage that contradicts the protocol's metadata privacy goals (Section 9.10).
- **Severity**: MEDIUM

### [7.7.1] DataProvenance `counterparties` Privacy Leak
- **Category**: Security-relevant omissions
- **Location**: Section 7.7.1 (line 515)
- **What's missing**: `counterparties: [DID]` lists all DIDs in the source interaction. When data flows through a outlet call from Context A to Context B, Context B's members see the full DID list of Context A's participants. This reveals Context A's membership to Context B. The spec does not analyze this privacy implication or provide a mechanism to redact counterparties.
- **Why it matters**: Counterparty revelation violates context isolation expectations. A member of a private context might not consent to their DID being revealed in provenance records to unknown contexts.
- **Severity**: HIGH

### [7.7] No Provenance Record Integrity Protection
- **Category**: Security-relevant omissions
- **Location**: Section 7.7.1-7.7.3 (lines 507-552)
- **What's missing**: Provenance records carry security-critical metadata (source context, counterparties, chain depth) but no signature or integrity protection is specified. Who signs the provenance record? The SDK that attaches it? The source context's governance key? If provenance is unsigned, any intermediary can forge or modify provenance records -- claiming data originated in a high-trust context when it did not, or reducing chain depth to bypass the depth limit.
- **Why it matters**: Unsigned provenance makes the entire provenance system gameable. An attacker can forge `PersistentVerifiable` provenance for data they fabricated, nullifying the quality evaluation system.
- **Severity**: CRITICAL

### [7.2/7.7] Spending UCAN Validation Timing Not Specified
- **Category**: Missing edge cases
- **Location**: Section 7.2 (line 64)
- **What's missing**: "For paid actions: spending UCAN is present and covers the cost." When are spending UCANs validated relative to action UCANs? Before? After? Simultaneously? If spending UCAN validation fails after the action UCAN has been validated and the action partially executed, what is the rollback behavior? Section 19 describes spending UCANs in detail but the validation ordering relative to action execution is not specified here.
- **Why it matters**: Without specified ordering, a race condition could allow an action to execute before spending validation completes, enabling free usage of paid features.
- **Severity**: MEDIUM

---

## Cross-File Consistency Issues

### Chain Depth: Hard Limit vs. Configurable
- **Location**: 06 line 37, 09 line 67, 24 line 116
- **Issue**: Section 06 says "protocol default: 3". Section 09 says "a hard protocol limit, not a governance option." Section 24 says "configurable per context but defaults to 3." These are contradictory. Is it a hard protocol limit or context-configurable?
- **Severity**: HIGH

### Capability Namespace Conflict
- **Location**: 06 line 74 (DID doc capabilities as freeform strings) vs. 07 line 268 (structured URI format)
- **Issue**: DID document `SCPCapabilities` example uses freeform strings ("translation", "japanese") while Section 7.3.4.1 mandates structured URIs (`scp:capability:*/v1` or `did:*:capability:*/v1`). These are incompatible formats.
- **Severity**: MEDIUM

### RFC 2119 Language Sparse
- **Location**: Both files
- **Issue**: Section 06 uses exactly one RFC 2119 keyword (one "MAY" at line 67). Section 07 uses four (three "MUST"/"MUST NOT" and one "MAY"). For protocol specification sections, this means the vast majority of requirements are stated in plain English without normative force. An implementor cannot distinguish between requirements and suggestions.
- **Severity**: MEDIUM

---

## Summary Statistics

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 17 |
| MEDIUM | 21 |
| LOW | 3 |
| **Total** | **45** |

The four CRITICAL findings are:
1. No wire format for cross-context outlet calls (06, Section 6.2.0)
2. UCAN capability matching algorithm not specified (07, Section 7.2)
3. Merkle tree construction not specified (07, Section 7.3.1)
4. No provenance record integrity protection (07, Section 7.7)

These four gaps mean that the core security primitives of both files -- cross-context data flow, authorization, verifiable logs, and data provenance -- are not deterministically implementable from the spec alone.
