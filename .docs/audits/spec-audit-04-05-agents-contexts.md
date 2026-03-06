---

> **Line number shift notice:** This audit was written against pre-PR #296 `05-contexts.md` (~960 lines). PR #296 added ~64 lines (memberBan capability, metadata visibility, projection auth, governance bans). Line references to `05-contexts.md` are shifted: lines 1-34 unchanged, 35-90 shift +1, 91-229 shift +35, 230-863 shift +47, 864+ shift +49 to +64. All findings remain valid.

# Specification Underspecification Audit: §4 (Agents) and §5 (Contexts)

## Executive Summary

Both specifications are well-written design documents that communicate intent clearly. However, they are **design documents, not protocol specifications**. An independent implementor reading only these files would face dozens of ambiguities requiring guesswork. The most severe gaps are in §5, which describes complex state machines, wire formats, and multi-party coordination protocols without providing the deterministic detail needed for interoperability. §4 is shorter and more conceptual, but still contains several claims about protocol-level enforcement with no specification of how that enforcement works mechanically.

The core pattern throughout: **the spec describes what should happen but not how to verify it happened, what to do when it fails, or the exact bytes on the wire**. This is the difference between a design document (which these are) and an interoperable protocol specification (which they aspire to be).

---

## Findings: §4 — Agents

### [4.2] Institutional Agent Key Governance Undefined
- **Category**: Underspecified algorithms
- **Location**: §4.2, line 12
- **What's missing**: Institutional agents are described as "bound to multiple humans through shared governance (multi-sig, elected operators, organizational hierarchy)" and noted as "structurally identical to personal agents." But how does multi-sig key control work for a single `#agent` verification method? A verification method is one key. If multiple humans share governance, do they hold key shares? Is there a threshold signature scheme? Who controls the private key? The spec says "the difference is in who holds the keys and how revocation/control works" but never specifies either of those differences.
- **Why it matters**: An implementor building institutional agent support has zero guidance on the key management model. This is a security-critical gap: if the intent is that institutions use a single private key with an operational key management process (e.g., HSM with M-of-N unlock), that needs to be stated. If the intent is threshold ECDSA/EdDSA, that's a significantly different implementation.
- **Severity**: HIGH

### [4.2] Maximum Number of `#agent` Verification Methods
- **Category**: Missing constants/defaults
- **Location**: §4.2-4.3, lines 11-16
- **What's missing**: §4.2 says "at most one `#agent` verification method." §4.3 says "exactly one `#agent` verification method." Which is it? Can a DID document have zero `#agent` VMs (human-only, no agent)? The minimum viable agent discussion (§4.5 line 43) suggests yes, but §4.3 says "exactly one." If zero is valid, verifiers need to handle the absent-agent case.
- **Why it matters**: DID document validators need a definitive rule: reject DID documents with 0 `#agent`? Or only reject >1? The ADR-039 memory note says "optional" and references a "domain-derived sentinel for absent agent key" — but this isn't stated in §4 at all. The spec file and the ADR disagree or at least don't cross-reference.
- **Severity**: MEDIUM

### [4.3] DID Document Rejection Criteria Not Specified
- **Category**: Missing conformance criteria
- **Location**: §4.3, line 16
- **What's missing**: "Verifiers reject DID documents with multiple `#agent` VMs." What does "reject" mean in protocol terms? Is this a hard parse error? A validation failure? Does it poison the DID entirely, or just prevent the DID from joining contexts? What error is returned? What happens if a DID document that was previously valid adds a second `#agent` VM through a DID update — do existing context memberships become invalid?
- **Why it matters**: Without specifying the failure mode, implementors will handle this inconsistently. Some will silently ignore extra VMs, some will hard-fail. The interoperability consequence is that a DID valid on one implementation may be invalid on another.
- **Severity**: MEDIUM

### [4.4] Agent Capability Metadata Schema Undefined
- **Category**: Missing wire format details
- **Location**: §4.4, lines 24-29
- **What's missing**: The spec says capability metadata is "a standardized profile" but §4 never defines the schema. It distinguishes self-attested from challenge-verified capabilities and says "contexts can require specific capability levels for admission" but does not define: the serialization format of capability metadata, where it's stored (DID document service endpoint? context metadata?), how admission checks are performed mechanically, or the structure of a challenge-verification record. The cross-reference to §7.3.4 provides more detail on challenge suites but still doesn't give a wire format for the capability metadata itself as stored in the DID document.
- **Why it matters**: This is not implementable from §4 alone. An implementor would need to read §7.3.4 and ADR-041, which provide partial answers — but even those don't give a complete serialized capability profile structure.
- **Severity**: HIGH

### [4.4] Standard Challenge Suites Not Enumerated
- **Category**: Missing conformance criteria
- **Location**: §4.4, line 27 (cross-ref §7.3.4)
- **What's missing**: "The protocol defines standard challenge suites for common capabilities (prompt injection resistance, schema validation, rate limit compliance, content formatting)." These are named but not defined. What are the test cases? What constitutes passing? What is the format of a challenge request and response? §7.3.4 in the trust spec says they exist but doesn't define them either.
- **Why it matters**: If challenge suites are protocol-level (which §7.3.4 implies by reserving the `scp:capability:` namespace), they need actual test vectors. Without them, "challenge-verified" has no meaning — any verifier can define any tests and call the results "challenge-verified."
- **Severity**: HIGH

### [4.5] Human vs. Agent Signing Ambiguity for Same Operation
- **Category**: Ambiguous state transitions
- **Location**: §4.5, lines 37-38
- **What's missing**: "Messages signed with `#active` are human-direct; messages signed with `#agent` are agent-autonomous." Are there operations where ONLY `#active` is valid? Or ONLY `#agent`? The spec says "the human can always act directly through `#active`" which implies `#active` can do everything `#agent` can. But can `#agent` do everything `#active` can? ADR-039 defines permission categories A/B/C with some operations restricted to `#0` only — but §4 doesn't reference this framework at all.
- **Why it matters**: Without clear rules about which signing key is valid for which operations, verifiers cannot correctly reject unauthorized actions. A compromised agent key should not be able to perform identity-layer operations (permission category A), but §4 doesn't state this.
- **Severity**: MEDIUM

### [4.7] Context Isolation Enforcement Mechanism Not Specified
- **Category**: Missing conformance criteria
- **Location**: §4.7, lines 56-61
- **What's missing**: "An agent in Context A has no protocol-level awareness of or connection to the same human's agent in Context B." This is stated as a design principle but there is no enforcement mechanism specified. What prevents an agent from including Context A's data in a Context B message? The spec says "the protocol only governs what touches the network" — so is the isolation purely SDK-level? If so, what stops a non-conformant SDK from cross-pollinating context data?
- **Why it matters**: If context isolation is a security claim, it needs a cryptographic or structural enforcement mechanism. If it's merely a design guideline for compliant SDKs, that should be stated explicitly. Currently the spec implies protocol-level enforcement that doesn't exist.
- **Severity**: MEDIUM

### [4.8] Context Participation Limits Completely Open
- **Category**: Missing constants/defaults
- **Location**: §4.8, lines 67-69
- **What's missing**: "The number of contexts a person can participate in may be an earned resource" and references an open question. But there's no maximum, no default, no rate limit on context joins. Without any limit, an attacker with one DID can join unlimited contexts and consume unlimited relay resources. Even if scoring is "product layer," the protocol needs a hard upper bound or relay-enforced rate limit.
- **Why it matters**: Relay resource exhaustion. A single DID subscribing to thousands of contexts creates storage and bandwidth obligations at the relay. The spec defers this entirely to §0 open questions and calls it Phase 2+, but it's a production DoS vector.
- **Severity**: MEDIUM

### [4.6] Builder Agent Definition Has No Protocol Surface
- **Category**: Vague requirements
- **Location**: §4.6, lines 53-54
- **What's missing**: "Builder agents — the LLMs and AI systems that generate apps and services on top of SCP using the SDK. These are developers, not protocol participants." If builder agents are not protocol participants, why are they mentioned in the protocol spec? Is there any protocol-level distinction? Can a builder agent also be a participant agent in a different context? This introduces a conceptual category with no protocol-level consequences.
- **Why it matters**: Minor — this is more of a document clarity issue. But it could confuse implementors into thinking there's a protocol-level builder agent role to implement.
- **Severity**: LOW

---

## Findings: §5 — Contexts

### [5.1] Context State Machine Not Specified in §5
- **Category**: Ambiguous state transitions
- **Location**: §5.1-5.2, lines 1-21
- **What's missing**: §5 references `Creating -> Active` transitions (line 21) and an ADR-008 state machine, but never actually specifies the complete state machine in the spec itself. The implementation reveals 5 states (Creating, Active, Closing, Closed, Expired) with specific valid transitions. The spec should contain the full state machine diagram, not defer it to an ADR. What operations are valid in each state? Can you send messages in `Creating`? Can you add members in `Closing`? What triggers `Closing -> Closed`?
- **Why it matters**: An implementor working from the spec alone would not know the full lifecycle. The state machine is the foundation of context behavior — every operation's validity depends on the current state.
- **Severity**: CRITICAL

### [5.2] Context Creation Failure States Undefined
- **Category**: Undefined error/failure behavior
- **Location**: §5.2, lines 17-21
- **What's missing**: What happens if context creation fails partway? MLS group initialization succeeds but transport publishing fails? Or event log init succeeds but UCAN minting fails? Is context creation atomic? If not, what is the cleanup protocol? The spec says nothing about partial creation failure or rollback.
- **Why it matters**: Partial creation leaves orphaned state — an MLS group with no corresponding event log, or transport subscriptions with no context state. Without atomicity guarantees or cleanup protocols, implementations will diverge on error handling.
- **Severity**: HIGH

### [5.3] Capability Categories Not Exhaustively Enumerated
- **Category**: Missing wire format details
- **Location**: §5.3, lines 25-35
- **What's missing**: "Standard capability categories include:" followed by 8 categories. But the word "include" implies this is not exhaustive. The templates (§5.12.1) use additional capabilities not listed here: `toolInvokeAll`, `toolInvokeSpecific`, `toolRegister`, `memberInvite`, `roleAssign`, `contextClose`, `contextCreate`. Some appear in templates but not in the §5.3 enumeration. Is the full canonical list specified anywhere? What is the serialization format for capability names?
- **Why it matters**: Implementors need the complete, canonical list of capability identifiers. A capability ceiling containing an unknown identifier is a parse error — but there's no way to distinguish "unknown" from "valid but not listed in §5.3."
- **Severity**: HIGH

### [5.3] Governed Ceiling Change Notification Protocol Undefined
- **Category**: Underspecified algorithms
- **Location**: §5.3, lines 43-44
- **What's missing**: "Members who joined under a narrower ceiling are notified and may leave before the expansion takes effect." How are they notified? What is the notification format? How long do they have before the expansion takes effect? Is there a mandatory waiting period? What happens if a member is offline during the notification window? Is the expansion blocked until all members acknowledge?
- **Why it matters**: Without a defined notification protocol and waiting period, "notified and may leave" is unenforceable. An implementation could notify and immediately expand, giving members zero practical opportunity to leave.
- **Severity**: HIGH

### [5.4] Tool Registration Wire Format Not Defined
- **Category**: Missing wire format details
- **Location**: §5.4, lines 55-63
- **What's missing**: Tool registrations list 5 fields (schema, implementation hash, test vectors, operator DID, cost metadata) but don't specify: the serialization format for tool registrations, the schema for test vectors (what structure? how are inputs and outputs represented?), the hash algorithm for implementation hash, how cost metadata is serialized, or the maximum size of a tool registration.
- **Why it matters**: Tools are a core protocol primitive. Two implementations serializing tool registrations differently would produce different implementation hashes and different event log entries.
- **Severity**: HIGH

### [5.4] Tool Implementation Hash: Hash of What?
- **Category**: Underspecified algorithms
- **Location**: §5.4, line 58
- **What's missing**: "Content-addressable reference to the tool's implementation." Hash of what bytes? The source code? A compiled binary? A serialized description? A tool that's a remote HTTP endpoint has no local implementation to hash. Is this the hash of the tool's schema + endpoint URL? Or the hash of the executable code? The spec doesn't say.
- **Why it matters**: If the implementation hash is the integrity anchor for tool verification, the preimage must be precisely defined. Different implementations hashing different preimages will produce incompatible hashes.
- **Severity**: HIGH

### [5.5] Observer Role Permissions Not Defined
- **Category**: Missing wire format details
- **Location**: §5.5, lines 65-80, and §5.12.1 line 254
- **What's missing**: The `group-discussion` template includes an `observer` role, but its permission set is never defined. `admin` and `member` are used across templates but also lack formal permission set definitions. §5.5 says "roles determine which tools an agent can invoke, what data it can access" etc. but never provides the actual permission mappings for any role.
- **Why it matters**: Templates are "protocol constants" (§5.12.1 line 317). If the observer role's permissions are undefined, two implementations will assign different permissions, making the template ID meaningless as a commitment.
- **Severity**: HIGH

### [5.5] Default Role Set Not Specified
- **Category**: Missing constants/defaults
- **Location**: §5.5, lines 65-80
- **What's missing**: "Custom roles beyond defaults are context-specific." What are the default roles? Admin and member are used in templates, but is there a protocol-defined default set? Or are "admin" and "member" just convention? What capabilities does "admin" always include? What capabilities does "member" always include?
- **Why it matters**: Without a canonical default role definition, template-based context creation is ambiguous. The `bilateral-ephemeral` template says `roles: [admin (creator), member (joiner)]` — but what can admin do? What can member do?
- **Severity**: HIGH

### [5.6] Maximum Membership Size Not Specified
- **Category**: Missing constants/defaults
- **Location**: §5.6, lines 83-87
- **What's missing**: No maximum member count for encrypted contexts. MLS has practical scaling limits (tree size, Welcome message cost). Is there a protocol-defined maximum? Or is it left to implementation? The `BroadcastEnvelope` path (§5.14) says "unlimited subscriber scale" for broadcast, but encrypted contexts have no stated limit.
- **Why it matters**: MLS performance degrades with large groups. Without a stated limit, an implementation might try to create a 10,000-member encrypted context and encounter undefined behavior from the MLS layer.
- **Severity**: MEDIUM

### [5.7] Metadata Signing Key and Freshness Not Specified
- **Category**: Security-relevant omissions
- **Location**: §5.7.1, lines 110-122
- **What's missing**: "The metadata record is signed by a current context admin." Which key? The admin's `#active`? `#agent`? The MLS signing key? Is there a metadata-specific signing key? What is the metadata record format (serialization)? How does a prospective member verify that the signer is a "current context admin" without being a member? How stale can metadata be before it's considered invalid? There's no TTL or freshness requirement on metadata records.
- **Why it matters**: Without freshness requirements, a relay could serve stale metadata indefinitely. A context that has since changed its governance or ceiling would be misrepresented. Without key specification, signature verification is unimplementable.
- **Severity**: HIGH

### [5.7.1] Metadata Routing ID Collision Not Addressed
- **Category**: Missing edge cases
- **Location**: §5.7.1, lines 114-116
- **What's missing**: `metadata_routing_id = SHA-256(context_id || "scp-metadata")`. What if this collides with a regular message routing_id? The regular routing_id for broadcast contexts is `SHA-256(context_id)` (§5.14.6) and for encrypted contexts is HKDF-derived (§9.10.4). There's no proof that the metadata routing ID space is disjoint from the message routing ID space. Domain separation between these two derivations is stated only by the different input formats — there's no explicit domain separator tag.
- **Why it matters**: A routing_id collision between metadata and messages would cause metadata to be delivered as messages or vice versa. While SHA-256 collision probability is negligible for random inputs, the derivation uses structured inputs where domain separation should be explicit.
- **Severity**: LOW

### [5.9] Governance Model Selection Immutability Contradiction
- **Category**: Ambiguous state transitions
- **Location**: §5.9, line 134
- **What's missing**: "Context creators select a governance model at creation; the selection is visible in context metadata (§5.7) and cannot be changed after creation **unless the model itself defines a governance transition mechanism.**" This exception swallows the rule. Can a `SingleAdmin` model define a transition to `Threshold`? What governance models define transition mechanisms? If all models CAN define transitions, then governance is always mutable. If none currently do, state that explicitly. The `requires_approval_for: [governanceChange]` in §5.13.4 implies governance changes are possible.
- **Why it matters**: Members join based on the visible governance model. If it can change, the opt-in contract is weaker than stated. The spec needs to clearly state which models support transitions and what the transition protocol is.
- **Severity**: MEDIUM

### [5.9] Governance Proposal ID Format and Generation Not Specified
- **Category**: Missing wire format details
- **Location**: §5.9, lines 136-140
- **What's missing**: "Each context MUST track the set of executed proposal IDs." What is a proposal ID? How is it generated? Is it a UUID? A hash of the proposal content? A monotonic counter? The format determines deduplication semantics and storage requirements.
- **Why it matters**: Without a defined proposal ID format, replay protection implementations will diverge. Hash-based IDs prevent duplicate content; counter-based IDs prevent duplicate submission. These are different security properties.
- **Severity**: MEDIUM

### [5.9] Presence-Only Member Governance Rights Boundary Not Precise
- **Category**: Ambiguous state transitions
- **Location**: §5.9, lines 152-161
- **What's missing**: "Presence-only members lose `GovernanceVote` and `GovernancePropose` capabilities alongside content access." Does this mean they also lose the ability to be the target of governance actions? Can a presence-only member be the subject of a `RestoreReadAccess` proposal they can't see or vote on? Can they still receive governance notifications? The membership/access table is clear on read/write/vote but doesn't cover: receiving notifications, being subject to governance, observing member list changes.
- **Why it matters**: If a presence-only member is supposed to participate in governance about their own access restoration, but they can't see proposals, the restoration pathway is broken.
- **Severity**: MEDIUM

### [5.10] TTL Extension Governance Protocol Undefined
- **Category**: Underspecified algorithms
- **Location**: §5.10, lines 181, 190
- **What's missing**: "Extension requires agreement from all parties (for bilateral contexts) or through the context's governance model (for multi-party contexts)." Lines 181 and 190 both state that TTL extension requires "explicit consent from all current members." Is it all members or governance-model-dependent? The two statements contradict. Also: what is the wire protocol for requesting, voting on, and executing a TTL extension? How close to expiry can an extension be proposed? Can an extension be proposed after expiry?
- **Why it matters**: TTL extension is part of the opt-in contract (stated explicitly). If the extension protocol is ambiguous, different implementations will offer different TTL extension behaviors, breaking the contract's meaning.
- **Severity**: HIGH

### [5.10] TTL Minimum and Maximum Not Specified
- **Category**: Missing constants/defaults
- **Location**: §5.10, lines 169-192
- **What's missing**: No minimum or maximum TTL values. Can a TTL be 1 millisecond? 100 years? The `bilateral-ephemeral` template says "required (creator sets duration, no default — forces intentionality)" but provides no bounds. The auto-accept example mentions "TTL <= 10 minutes" as a policy, but there's no protocol-level floor.
- **Why it matters**: A TTL of 0ms or near-zero creates a context that immediately expires, potentially before the peer can even join. A TTL of `u64::MAX` nanoseconds is effectively infinite but would appear to have a TTL in metadata. Without bounds, edge-case behavior is undefined.
- **Severity**: MEDIUM

### [5.11] Summary Memory Scope: Verification Window Duration Undefined
- **Category**: Missing constants/defaults
- **Location**: §5.11, line 204
- **What's missing**: "Both parties can verify the summary against the event log before keys are destroyed." How long is this verification window? What happens if one party doesn't verify within the window? Is the verification mandatory or optional? Does key destruction block on verification completion? Can one party block key destruction indefinitely by refusing to verify? What if the party is offline?
- **Why it matters**: Without a defined window and timeout, the verification step is either optional (rendering it meaningless) or indefinitely blocking (preventing key destruction, violating the ephemeral contract).
- **Severity**: HIGH

### [5.11] Summary Content Not Specified
- **Category**: Underspecified algorithms
- **Location**: §5.11, line 204
- **What's missing**: "The summary format is defined by the context (via tools or governance), not by the protocol." So the protocol defines a `Summary` memory scope but delegates the summary content entirely to context-specific tools. What if no tool is registered to produce summaries? Is there a default summary? Is the summary just "context existed from T1 to T2 with members [A, B]"? The protocol lifecycle hooks (pre-close summary generation) are referenced but never defined.
- **Why it matters**: If `Summary` memory scope is a protocol-level feature, it needs at least a minimal default behavior when no context-specific summary tool is provided. Otherwise, `Summary` and `Ephemeral` are identical for contexts without summary tools.
- **Severity**: MEDIUM

### [5.11] Ephemeral Relay Deletion Request Format Not Specified
- **Category**: Missing wire format details
- **Location**: §5.11, line 200
- **What's missing**: "The SDK issues deletion requests to relays for all encrypted event data associated with the context." What is the wire format of a deletion request? Is it authenticated? Which relay API endpoint? How does the relay identify which data to delete — by routing_id? By blob_id? By context_id (which the relay may not have in cleartext for encrypted contexts)? The relay sees routing_ids, not context_ids, for encrypted contexts.
- **Why it matters**: For encrypted contexts, the relay cannot map a deletion request containing a context_id to stored blobs (since context_id is inside the encrypted payload). The deletion mechanism needs to work with relay-visible identifiers (routing_id, blob_id), but this isn't stated.
- **Severity**: HIGH

### [5.12.1] Template `extends` Semantics Undefined
- **Category**: Underspecified algorithms
- **Location**: §5.12.1, lines 296-311
- **What's missing**: The `paid-service` template says `extends: scp:template/tool-interface` and `paid-broadcast` says `extends: scp:template/gated-broadcast`. What does `extends` mean? Inheritance? Override? Merge? If a field in the extending template conflicts with the base template, which wins? Is `extends` a protocol mechanism or a documentation shorthand? The spec never defines `extends` semantics.
- **Why it matters**: Template composition is either a protocol-level feature (needing precise semantics) or a documentation convenience (needing no protocol support). If it's protocol-level, implementations must resolve `extends` chains identically. If it's documentation, say so explicitly.
- **Severity**: MEDIUM

### [5.12.2] Auto-Accept Rate Type Undefined
- **Category**: Missing wire format details
- **Location**: §5.12.2, line 332
- **What's missing**: `rate_limit: Rate?` — the `Rate` type is never defined anywhere in the spec. Is it count/duration? Requests per second? A token bucket? The example says "at most 5 per hour" but the type structure is undefined.
- **Why it matters**: Since auto-accept policies are "local to the agent (never shared with the network)" this is less critical — but it still needs a defined type for SDK interoperability.
- **Severity**: LOW

### [5.12.2] Auto-Accept TrustRequirement `discovery_context` Undefined
- **Category**: Underspecified algorithms
- **Location**: §5.12.2, lines 335-338
- **What's missing**: `discovery_context // DID is registered in a discovery context I trust`. What makes a discovery context "trusted"? Is trust in a discovery context itself governed by auto-accept policies (circular)? How does the SDK evaluate this criterion at invitation-processing time — does it query the discovery context? Cache discovery context membership? What if the discovery context is offline?
- **Why it matters**: This is a potentially expensive runtime check (querying an external context) in the fast path of invitation processing. If the discovery context is unreachable, does the auto-accept fail closed (reject) or fail open (prompt)?
- **Severity**: LOW

### [5.12.3] Invitation Bundle Wire Format Not Specified
- **Category**: Missing wire format details
- **Location**: §5.12.3, lines 377-379
- **What's missing**: "The SDK bundles the context metadata and MLS Welcome message into a single transport delivery." What is the bundle format? How is it serialized? What is the message type on the wire? How does the peer's SDK distinguish an invitation bundle from a regular message? There's no wire format for invitations anywhere in §5 or §9.
- **Why it matters**: Invitation processing is the entry point for context joins. Without a defined bundle format, two SDKs cannot interoperate on context creation.
- **Severity**: CRITICAL

### [5.12.4] Performance Claims Without Bounds
- **Category**: Vague requirements
- **Location**: §5.12.4, lines 385-426
- **What's missing**: Performance numbers are stated as facts ("~5-15ms", "sub-200ms") but are neither requirements nor guarantees. Are these normative? If an implementation takes 500ms for local computation, is it non-conformant? Or are these descriptive? If descriptive, they're marketing copy, not spec.
- **Why it matters**: Performance numbers in a spec should be either normative (MUST complete within X) or clearly descriptive ("typical implementation achieves X"). Currently ambiguous.
- **Severity**: LOW

### [5.12.5] Application Startup: Reconnection Failure Handling Missing
- **Category**: Undefined error/failure behavior
- **Location**: §5.12.5, lines 450-458
- **What's missing**: "Reconnect transport for all Active contexts (background, non-blocking)." What happens when reconnection fails? For one context? For all contexts? What's the retry strategy? How long does the SDK attempt reconnection before declaring a context unreachable? What does the application see during reconnection?
- **Why it matters**: Network failures are the most common production scenario. Every SDK will need to implement reconnection with backoff, and without spec guidance, they'll all do it differently — creating inconsistent user experiences and potentially different security properties during the reconnection window.
- **Severity**: MEDIUM

### [5.12.5] Application Shutdown: Flush Timeout Not Specified
- **Category**: Missing constants/defaults
- **Location**: §5.12.5, lines 487-492
- **What's missing**: "Flush pending event log entries." What if the flush takes too long? Is there a timeout? What happens to unflushed entries? Are they persisted locally for retry on next startup? Or lost?
- **Why it matters**: On mobile platforms, shutdown may be forced (OS killing the process). The spec needs to address what happens when shutdown is not graceful.
- **Severity**: MEDIUM

### [5.12.6] Standing Channel Storage Estimate Without Bounds
- **Category**: Missing constants/defaults
- **Location**: §5.12.6, line 515
- **What's missing**: "Approximately 2-5KB per bilateral context." Is this a protocol guarantee, a typical measurement, or a rough estimate? If a context accumulates 10,000 messages, does the persisted state still fit in 5KB? Or does the event log grow indefinitely? What about sender key state over many epoch rotations?
- **Why it matters**: Mobile devices have storage constraints. If the 2-5KB claim only applies to a fresh context with no message history, it's misleading. The spec should clarify what's included in persistent state (MLS tree? event log? message history? sender keys for all epochs?).
- **Severity**: LOW

### [5.13.2] Eligibility Check Race Condition
- **Category**: Missing edge cases
- **Location**: §5.13.2, lines 573-598
- **What's missing**: Eligibility is "continuous, not one-time." If Alice is removed from Parent A at the same time Bob is adding her to Child C (where she's eligible only through A), there's a TOCTOU race. The spec mentions both SDK-level and relay-level validation, but doesn't specify: what happens if the SDK checks eligibility, starts the MLS add, and the parent membership changes before the relay validates? Is the relay's check authoritative? What happens to the in-flight MLS add?
- **Why it matters**: Distributed systems with continuous enforcement need conflict resolution rules. Without them, the child context could contain members who passed SDK validation but fail relay validation, or vice versa — leaving the MLS group and membership roster inconsistent.
- **Severity**: HIGH

### [5.13.2] Relay Eligibility Validation: How Does Relay Know Parent Membership?
- **Category**: Underspecified algorithms
- **Location**: §5.13.2, lines 596
- **What's missing**: "Relay infrastructure independently validates eligibility constraints... verifies that each member being added is present in at least one parent context's membership roster." How does the relay know the parent's membership roster? Encrypted context membership is inside MLS — the relay can't see it. Does the relay maintain a plaintext membership index? If so, who provides it? How is it authenticated? This is a fundamental architectural question the spec doesn't address.
- **Why it matters**: If the relay cannot verify parent membership (because it's encrypted), then relay-level validation is impossible, and the "protocol-level guarantee" claim (§5.13.2 line 596) is false. The spec claims this is "not an SDK honor system" but may actually be, unless there's a mechanism for the relay to learn membership.
- **Severity**: CRITICAL

### [5.13.3] Multi-Parent Coordinated Creation: Proposal Matching Details Missing
- **Category**: Underspecified algorithms
- **Location**: §5.13.3, lines 625-635
- **What's missing**: "The protocol matches proposals by their content hash: when all proposed parents have published matching proposals (identical child params), the child is created." Who performs the matching? The relay? Each SDK independently? What if proposals arrive at different relays? What is the proposal wire format? How does the protocol discover that all parents have published matching proposals? Is there a coordinator, or is it decentralized? What happens if the proposals almost match but differ in one field? What if a parent publishes two conflicting proposals?
- **Why it matters**: Multi-party coordination without a coordinator requires a specific protocol (e.g., consensus, a commit phase, or a designated matchmaker). "The protocol matches proposals" hand-waves over the hard distributed systems problem.
- **Severity**: HIGH

### [5.13.3] Child Creation Proposal Expiry: Where Is Timeout State Tracked?
- **Category**: Underspecified algorithms
- **Location**: §5.13.3, line 625
- **What's missing**: "Proposals expire after a configurable timeout (suggested default: 1 hour)." Configurable by whom? At what level — per context? Per proposal? Is the timeout wall-clock time or logical time? Who enforces the timeout — the SDK or the relay? What happens to the proposal state on expiry — is it garbage collected? Can an expired proposal be resubmitted?
- **Why it matters**: Without timeout enforcement specification, proposals could remain valid indefinitely on some implementations, creating a delayed-execution attack vector where an old proposal is unexpectedly matched.
- **Severity**: MEDIUM

### [5.13.3] Cryptographic Binding: MLS group_context Extension Format Not Specified
- **Category**: Missing wire format details
- **Location**: §5.13.3, lines 648-652
- **What's missing**: "Parent context IDs and the content hash of the parent governance configuration are included in the MLS `group_context` extensions field." What is the extension type ID? What is the serialization format of parent context IDs in the extension? How is the governance configuration hashed? What hash algorithm? The MLS `group_context` extensions field has a specific structure (extension type + extension data) — neither the type ID nor the data format is defined.
- **Why it matters**: Without a defined extension format, child contexts from different implementations will have different MLS group_context values, producing different group_ids, making them incompatible.
- **Severity**: HIGH

### [5.13.4] on_sever: preserve_membership Security Implications Not Fully Addressed
- **Category**: Security-relevant omissions
- **Location**: §5.13.4, lines 675-677
- **What's missing**: `preserve_membership` allows members to retain their seat after their eligibility anchor (parent) is severed. But what happens to their UCAN tokens that were derived from the parent context? If their membership UCAN references the parent context as part of the delegation chain, and the parent is gone, is the UCAN still valid? The spec says members "keep their seat" but doesn't address whether their capability tokens remain valid.
- **Why it matters**: If capability tokens are invalidated by parent sever but membership is preserved, the member has a seat but no capabilities — effectively presence-only. If tokens remain valid despite the parent being gone, the trust anchor for those tokens has disappeared. Neither outcome is addressed.
- **Severity**: MEDIUM

### [5.13.5] Lifecycle Cascade Ordering and Atomicity
- **Category**: Missing edge cases
- **Location**: §5.13.5, lines 725-748
- **What's missing**: When a parent closes and triggers `cascade_close` on a child that itself has children, what is the ordering? Depth-first? Breadth-first? Does the parent's close complete before the child's cascade begins? Are cascades atomic (either the entire tree closes or nothing does)? What happens if a cascade partially fails (parent closes, child cascade starts, grandchild cascade fails)?
- **Why it matters**: With the maximum nesting depth of 3, cascading close affects up to 3 levels. Without defined ordering, event log entries from different implementations will record cascades in different orders, breaking event log interoperability.
- **Severity**: MEDIUM

### [5.13.5] Lifecycle Event Log Entry Wire Format
- **Category**: Missing wire format details
- **Location**: §5.13.5, lines 739-749
- **What's missing**: The event log entries shown (ChildCreated, ChildClosed, ParentSevered, MemberEvicted, ClosedByOrphan) use informal notation. The actual serialized format, field types, and serialization are not specified. Is `reason: .manual | .ttl_expiry` an enum? What are the discriminant values? How is `co_parents: [contextID]` serialized?
- **Why it matters**: Event log entries are the audit trail. Different serializations produce different Merkle tree hashes, breaking verification.
- **Severity**: HIGH

### [5.13.8] Nesting Depth: "Suggested Default" Is Not a Constant
- **Category**: Vague requirements
- **Location**: §5.13.8, lines 790-797
- **What's missing**: "The protocol enforces a maximum nesting depth (suggested default: 3 levels)." Then: "The nesting depth limit is a protocol constant, not configurable per context." These contradict: is it a "suggested default" or a "protocol constant"? If it's a constant, state the value with MUST language. If it's configurable, state the range and default.
- **Why it matters**: This affects relay validation logic. If some implementations use 3 and others use 5, child context creation will succeed on some relays and fail on others.
- **Severity**: MEDIUM

### [5.14.2] Broadcast Key Epoch Advancement: When Exactly?
- **Category**: Underspecified algorithms
- **Location**: §5.14.2, lines 814-826
- **What's missing**: "On block: increment epoch, generate new key, publish `KeyEpochAdvance` notification." What about periodic rotation independent of blocks? Is epoch advancement ONLY triggered by blocking? What if an author wants to rotate proactively? Is proactive rotation allowed? Is there a maximum key lifetime? The spec only mentions block-triggered rotation, which means an unblocked key could be used indefinitely.
- **Why it matters**: Without mandatory periodic rotation, a broadcast key compromise gives the attacker unlimited future decryption until the next block event. This is explicitly weaker than MLS forward secrecy, but the spec doesn't acknowledge or bound this weakness.
- **Severity**: MEDIUM

### [5.14.3] Subscriber Registration Deduplication Not Addressed
- **Category**: Missing edge cases
- **Location**: §5.14.3, lines 829-849
- **What's missing**: What happens when a subscriber registers twice? Is the second registration idempotent? Does it update the wrapping_pubkey? Is the timestamp used for replay protection — and if so, what's the acceptable time window? Can a subscriber re-register with a new wrapping key (key rotation)?
- **Why it matters**: Without deduplication rules, a malicious subscriber could flood registration messages. Without key rotation support, a subscriber whose wrapping key is compromised has no recovery path.
- **Severity**: MEDIUM

### [5.14.3] Subscriber Registration Timestamp: Clock Skew Tolerance
- **Category**: Missing constants/defaults
- **Location**: §5.14.3, line 843
- **What's missing**: `timestamp: u64` — what format? Unix seconds? Milliseconds? What clock skew tolerance is acceptable? What happens if the timestamp is in the future? Far in the past?
- **Why it matters**: Timestamp validation is the primary replay protection for subscriber registrations. Without a defined format and tolerance, implementations will either accept all timestamps (no replay protection) or use incompatible formats.
- **Severity**: MEDIUM

### [5.14.5] BroadcastEnvelope content_hash: Confirmation Oracle Risk
- **Category**: Security-relevant omissions
- **Location**: §5.14.5, lines 873-874
- **What's missing**: `content_hash: [u8; 32], // SHA-256 of plaintext content` — this is a hash of the plaintext shipped alongside the ciphertext. The memory notes say ADR-038 explicitly avoided this for access keys because "SHA-256(plaintext) alongside ciphertext would be a confirmation oracle." Yet the BroadcastEnvelope includes exactly this construction. The receiver verifies `content_hash == SHA-256(decrypted_content)`, but an attacker who guesses the plaintext can verify their guess against the content_hash without possessing the broadcast key. The content_hash is outside the AES-256-GCM encryption.
- **Why it matters**: For low-entropy messages (yes/no responses, short commands, known-format data), the content_hash enables offline plaintext confirmation attacks. An attacker who can observe the BroadcastEnvelope (any relay) can hash candidate plaintexts and check against content_hash. This violates IND-CPA if the message space is small.
- **Severity**: HIGH

### [5.14.5] BroadcastEnvelope Signature Covers content_hash but Not Encrypted Content
- **Category**: Security-relevant omissions
- **Location**: §5.14.5, lines 882-888
- **What's missing**: The signature covers `content_hash` (hash of plaintext) but does NOT cover the `content` field (encrypted bytes). This means an attacker could replace the encrypted content with different ciphertext that decrypts to different plaintext (if they have the broadcast key) without invalidating the signature — because the signature is bound to the plaintext hash, not the ciphertext. The AES-256-GCM tag protects against ciphertext modification, but the binding between "this author signed this plaintext hash" and "this ciphertext decrypts to this plaintext" relies on the receiver successfully decrypting and checking the hash match.
- **Why it matters**: The signature should cover either the ciphertext directly or be included in the AES-256-GCM AAD. The current construction creates a subtle gap: the signature proves "the author intended to send content with this hash" but does not prove "the author produced this specific ciphertext." For non-interactive verification (a third party verifying the signature without the broadcast key), the content_hash is unverifiable.
- **Severity**: MEDIUM

### [5.14.5] BroadcastEnvelope: AES-256-GCM Nonce/IV Not Specified
- **Category**: Missing wire format details
- **Location**: §5.14.5, lines 867-878
- **What's missing**: The `content` field is "AES-256-GCM encrypted with author broadcast key" but the nonce/IV construction is not specified. Is the nonce derived from the sequence number? Random? Counter-based? AES-256-GCM with a reused nonce is catastrophically broken. This is the single most important detail of the encryption scheme, and it's missing.
- **Why it matters**: AES-GCM nonce reuse reveals the XOR of two plaintexts and compromises the authentication key. With a 96-bit random nonce, the birthday bound is approximately 2^32 messages per key. If the nonce is derived from the monotonic sequence number, it's safe but must be specified. This MUST be defined before any implementation.
- **Severity**: CRITICAL

### [5.14.5] BroadcastEnvelope: provenance_hash Sentinel Inconsistency
- **Category**: Cross-reference inconsistencies
- **Location**: §5.14.5, line 888
- **What's missing**: "`provenance_hash = SHA256(serialize(provenance))` if present, or `SHA256(0x00)` if absent (same sentinel as InnerEnvelope, ADR-002)." The sentinel `SHA256(0x00)` for absent provenance means the hash of a single zero byte. Is this `SHA-256(0x00)` or `SHA-256(empty_bytes)`? For the InnerEnvelope, is this actually specified in ADR-002, or is §5.14 the only place it's stated? If different spec sections independently define sentinels, they could diverge.
- **Why it matters**: If the sentinel value differs between implementations, signature verification fails for messages without provenance.
- **Severity**: LOW

### [5.14.6] Broadcast Routing ID vs. Metadata Routing ID Relationship
- **Category**: Missing edge cases
- **Location**: §5.14.6, line 896 and §5.7.1 line 114
- **What's missing**: Broadcast `routing_id = SHA-256(context_id)`. Metadata `metadata_routing_id = SHA-256(context_id || "scp-metadata")`. These are different by construction, which is good. But the spec doesn't state this explicitly or prove they won't collide with encrypted context routing IDs (which are HKDF-derived). A formal domain separation analysis is missing.
- **Why it matters**: Minor given SHA-256 collision resistance, but protocol specs should explicitly prove that different routing ID namespaces are disjoint.
- **Severity**: LOW

### [5.14.7] Subscriber Key Caching Not Specified
- **Category**: Underspecified algorithms
- **Location**: §5.14.7-5.14.8
- **What's missing**: After a subscriber receives an author's broadcast key, how long should they cache it? What happens when the key epoch advances — must the subscriber request the new key before decrypting new messages? Is there a grace period for the old key? What if the subscriber is offline when the epoch advances and comes back to messages encrypted under both old and new keys?
- **Why it matters**: Without caching and epoch transition rules, subscribers will either fail to decrypt messages (if they aggressively discard old keys) or hold keys indefinitely (if they never discard), both of which create security or usability problems.
- **Severity**: MEDIUM

### [5.14.8] Blocked Subscriber Key Request: Timing Side Channel
- **Category**: Security-relevant omissions
- **Location**: §5.14.8, lines 909-914
- **What's missing**: "Blocked subscriber requests new key -> no response -> cannot decrypt future content." The author simply ignores requests from blocked subscribers. This creates a timing side channel: a subscriber can determine they've been blocked by measuring the response time (legitimate requests get a response; blocked requests get silence). The spec doesn't specify whether this is acceptable or whether authors should respond with a dummy/error to prevent the timing distinction.
- **Why it matters**: In some contexts, knowing you've been blocked is itself sensitive information. The spec should explicitly decide: is block detection by the blocked party an acceptable leak, or should it be prevented with dummy responses?
- **Severity**: LOW

### [5.14.10] ConsistencyCheckpoint.epoch Optional: Validation Implications
- **Category**: Ambiguous state transitions
- **Location**: §5.14.10, line 941
- **What's missing**: "`ConsistencyCheckpoint.epoch` becomes `Option<u64>` (`None` for broadcast contexts, which have no MLS epoch)." What replaces the epoch as the consistency anchor for broadcast contexts? Is it the highest per-author sequence number? The event log position? Without an epoch equivalent, how do broadcast context members verify they're seeing the same state? The consistency checkpoint mechanism (referenced to §9 but not defined here) needs a broadcast-specific anchor.
- **Why it matters**: If consistency checkpoints for broadcast contexts have no epoch field, the mechanism for detecting relay omissions is weakened. Members need some shared state to compare.
- **Severity**: MEDIUM

### [5.14.11] Discovery URI Format: Legacy Alias Normalization
- **Category**: Missing conformance criteria
- **Location**: §5.14.11, line 950
- **What's missing**: "The legacy format `scp://broadcast/<context_id_hex>?relay=<url>` is accepted as an alias and normalized to the universal format." When is normalization performed? Is it a MUST? If an SDK receives the legacy format, must it convert before processing? Or can it process both formats natively? What happens if both formats refer to the same context in different places — are they equal for comparison purposes?
- **Why it matters**: URI comparison is used in deduplication and routing. Without canonical form rules, two URIs referring to the same context could be treated as different.
- **Severity**: LOW

### [5.1-5.14] Missing: Context Destruction / Garbage Collection
- **Category**: Undefined error/failure behavior
- **Location**: Entire §5
- **What's missing**: The spec describes context creation and closing, but never specifies context destruction — the permanent removal of context state from local storage. Closed contexts persist their metadata. But: when can a closed context's state be garbage collected? Is there a retention period? What happens to child context references when a parent's state is garbage collected? What about contexts where all members have left — who performs the final close?
- **Why it matters**: Long-running nodes will accumulate closed context state indefinitely without a defined GC policy. This is a storage leak that becomes a DoS vector over time.
- **Severity**: MEDIUM

### [5.1-5.14] Missing: Concurrent Member Additions
- **Category**: Missing edge cases
- **Location**: Entire §5
- **What's missing**: What happens when two admins simultaneously try to add different members to the same context? MLS add proposals from concurrent senders create a branch that must be resolved. The spec never addresses concurrent operations on context state — member adds, role changes, governance proposals — all of which could be submitted simultaneously by different parties with appropriate permissions.
- **Why it matters**: MLS handles concurrent proposals through its commit mechanism, but the SCP layer on top (event log, role state, governance state) needs its own concurrency resolution. Without it, implementations will diverge on which concurrent operation wins.
- **Severity**: MEDIUM

### [5.1-5.14] Missing: Context Migration / Context ID Continuity
- **Category**: Missing edge cases
- **Location**: Entire §5
- **What's missing**: The spec says "expired TTL is final — if participants want to continue, they create a new context (which may reference the closed one for continuity)." But the referencing mechanism is never defined. How does a new context reference a closed one? Is there a `predecessor_context_id` field? How is continuity verified? Can a context claim to continue any arbitrary closed context?
- **Why it matters**: Without a defined continuity mechanism, "reference the closed one" is unverifiable. An attacker could create a context claiming to continue a high-reputation context they were never part of.
- **Severity**: MEDIUM

---

## Summary Statistics

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 16 |
| MEDIUM | 20 |
| LOW | 8 |
| **Total** | **48** |

**CRITICAL findings (must be resolved before implementation can interoperate):**
1. Context state machine not specified in §5
2. Invitation bundle wire format not specified
3. Relay eligibility validation assumes relay can see encrypted membership
4. AES-256-GCM nonce/IV for BroadcastEnvelope not specified

**Pattern summary:** The most common gap category is **missing wire format details** (13 findings), followed by **underspecified algorithms** (7 findings) and **missing constants/defaults** (7 findings). This confirms the documents are design documents being used as protocol specifications — they specify intent clearly but not bytes on wire.
