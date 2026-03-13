# Specification Audit: Unspecified Details in Specs 12-15

**Auditor:** Adversarial Expert (independent protocol security review)
**Date:** 2026-03-05
**Scope:** specs/12-platform-bridge-connectors.md, specs/13-versioning-and-protocol-evolution.md, specs/14-protocol-governance.md, specs/15-regulatory-compliance.md
**Method:** Line-by-line reading, cross-reference verification against other spec sections and implementation code, adversarial analysis

---

## Executive Summary

Spec 12 (Platform Bridge Connectors) is by far the most substantial of these four files and is the only one with meaningful protocol-level content requiring detailed implementation. It is partially well-specified (the cooperative mode HTTP binding in 12.10-12.11 is thorough) but has significant gaps in the bridge registration protocol, shadow identity lifecycle, security model for bridge operators, and integration with the rest of the protocol machinery. Specs 13, 14, and 15 are intentionally high-level vision documents rather than normative protocol specifications, but even at that level they omit details that will become blocking ambiguities when someone tries to implement against them.

**Total findings: 62**
- CRITICAL: 6
- HIGH: 18
- MEDIUM: 27
- LOW: 11

---

## Spec 12: Platform Bridge Connectors (42 findings)

### [12.2-001] Bridge Registration Protocol Unspecified
- **Category**: Underspecified algorithms
- **Location**: 12.2
- **What's missing**: 12.2 states bridges "register with a specific context" and "the context's governance model controls whether the bridge is admitted." The actual registration protocol is never defined. What wire message does the operator send? What governance action type approves a bridge? How does the registration appear in the event log? The implementation in `registration.rs` has `register_bridge()` / `approve_registration()` / `reject_registration()` but the spec defines none of these as protocol operations.
- **Why it matters**: Two independent implementations would produce incompatible registration flows. The governance integration for bridge admission is unspecified -- does it use the existing `GovernanceAction` enum, or does it need new variants?
- **Severity**: HIGH

### [12.2-002] Bridge Removal Protocol Unspecified
- **Category**: Ambiguous state transitions
- **Location**: 12.2
- **What's missing**: "Context governance can remove a bridge at any time, severing the connection to the external platform." No specification of what "remove" means at the protocol level. Is this a `GovernanceAction::RevokeBridge`? Does it destroy shadow identities or just disconnect them? What events are emitted? What happens to in-flight messages from shadows? The implementation has `revoke_bridge()` but the wire protocol and event log entries are unspecified.
- **Why it matters**: Removal must be an atomic, auditable operation. Without specification, implementations may leave bridges in inconsistent states or fail to properly record revocation in the Merkle log.
- **Severity**: HIGH

### [12.2-003] Bridge Suspension vs Revocation State Machine Undefined
- **Category**: Ambiguous state transitions
- **Location**: 12.2
- **What's missing**: `BridgeStatus` has three states: `Active`, `Suspended`, `Revoked`. The spec never defines the state transition rules. Can a `Revoked` bridge be reinstated? Can `Suspended` go directly to `Revoked`? Can `Active` be created from `Revoked`? The implementation in `mod.rs` defines the enum but has no transition guards. 12.11.1 phase 5 mentions suspension and revocation semantics for credentials but not for the status transitions themselves.
- **Why it matters**: Without a defined state machine, implementations may allow invalid transitions (e.g., reactivating a revoked bridge, which would undermine governance decisions).
- **Severity**: MEDIUM

### [12.3-001] Shadow Identity Maximum Count Per Bridge Unspecified
- **Category**: Missing constants/defaults
- **Location**: 12.3
- **What's missing**: No limit on shadow identities per bridge. A bridge operator could create millions of shadows, exhausting storage and processing resources in the context. The status endpoint (12.10.4) shows `shadow_count` and notes pagination for "large rosters" but never defines what "large" means or imposes a limit.
- **Why it matters**: Resource exhaustion attack. A malicious bridge operator creates unbounded shadow identities, bloating the context's event log and consuming storage. This is a production-critical constraint that must have a default and a governance-configurable maximum.
- **Severity**: HIGH

### [12.3-002] Shadow Identity ID Generation Algorithm Unspecified
- **Category**: Underspecified algorithms
- **Location**: 12.3
- **What's missing**: `shadow_id` is a `String` in both spec and implementation. No specification of how shadow IDs are generated. Are they UUIDs? Platform-specific? Deterministic from `bridge_id + platform_user_id`? If deterministic, what is the derivation? If random, what entropy source?
- **Why it matters**: ID generation affects deduplication, idempotency, and cross-implementation interoperability. If two implementations generate different IDs for the same shadow, the event logs diverge.
- **Severity**: MEDIUM

### [12.3-003] Shadow Role Default "observer" Not Defined Elsewhere
- **Category**: Cross-reference inconsistencies
- **Location**: 12.3
- **What's missing**: Shadows default to `"observer"` role. The role is stored as a `String` in `ShadowIdentity.attributed_role`. The context role system (5.5) does not define `"observer"` as a well-known role. There is no specification of what permissions the `observer` role has. The implementation in `shadow.rs` references `VERIFIED_IDENTITY_CAPABILITIES` to restrict shadows, but the actual role definition is not in any spec section.
- **Why it matters**: An implementor reading 5.5 (roles) would not know what `observer` means or what permissions it has. The restriction mechanism (capability gating based on identity verification status) is implementation-specific and not spec-normative.
- **Severity**: MEDIUM

### [12.3-004] Shadow Claiming Race Condition With Multiple Claimants
- **Category**: Missing edge cases
- **Location**: 12.3
- **What's missing**: What if two users both claim ownership of the same external platform handle and try to claim the same shadow simultaneously? The spec says claiming is "one-way and irreversible" so first-to-claim wins, but there is no specification of conflict resolution. What if an external platform handle changes ownership (e.g., username recycling on Twitter)?
- **Why it matters**: Username recycling is common on social platforms. A handle `@alice` that was owned by Person A when the shadow was created might be owned by Person B when claiming happens. The protocol has no mechanism to verify current handle ownership, only attestation presentation.
- **Severity**: MEDIUM

### [12.3-005] Claimed Shadow Role Upgrade Path Unspecified
- **Category**: Ambiguous state transitions
- **Location**: 12.3
- **What's missing**: 12.3 says shadows are "restricted by default" and context governance "may subsequently upgrade the role." But once a shadow is claimed (bound to a DID), the spec doesn't address what happens to the shadow's role. Does the claimant inherit the shadow's observer role? Does claiming automatically upgrade to full member? Does the claimant need to separately join the context?
- **Why it matters**: The transition from claimed shadow to full participant is ambiguous. An implementor must decide whether claiming creates a new membership entry or mutates the shadow in place.
- **Severity**: HIGH

### [12.3-006] Shadow Identity Storage and Retrieval Not Specified in 17
- **Category**: Cross-reference inconsistencies
- **Location**: 12.3, 17.3
- **What's missing**: Spec 17 (persistence) defines key conventions for all protocol state. Shadow identities are not mentioned in the ProtocolRepository key convention. How are shadows stored? Under what key path? Are they part of context state or bridge state?
- **Why it matters**: Without a defined storage convention, implementations will use ad-hoc storage that may not interoperate with the version envelope system (StoredValue) or be included in context export/import flows.
- **Severity**: MEDIUM

### [12.4-001] Mode Transition Rules Unspecified
- **Category**: Ambiguous state transitions
- **Location**: 12.4
- **What's missing**: Can a bridge change its operating mode after registration? For example, can a bridge start in Relay mode and upgrade to Cooperative mode? The spec defines four modes but says nothing about whether mode transitions are allowed, require governance approval, or are immutable at registration.
- **Why it matters**: Mode determines trust evaluation (12.5) and provenance marking (12.10.6). Changing mode mid-lifecycle changes the trust properties of all subsequent messages. If mode is mutable, there should be governance gating and event log recording.
- **Severity**: MEDIUM

### [12.5-001] Trust Hierarchy Does Not Address Cooperative-Specific Trust
- **Category**: Cross-reference inconsistencies
- **Location**: 12.5, 12.10.6
- **What's missing**: The trust hierarchy in 12.5 defines four tiers on two axes (identity x transport). 12.10.6 states cooperative mode content receives "enhanced trust evaluation" but the four-tier hierarchy in 12.5 does not distinguish cooperative from non-cooperative bridges. A shadow on a cooperative bridge and a shadow on a relay bridge both evaluate to `ShadowBridged`. The spec says "Trust engines (7) and agents MAY treat cooperative-mode provenance as a positive signal" but this is advisory, not structural.
- **Why it matters**: The cooperative mode incentive argument (12.9) depends on cooperative mode producing measurably better trust evaluation. If the protocol's own trust model doesn't distinguish it, the incentive is hollow.
- **Severity**: MEDIUM

### [12.5-002] Bridge Provenance Not Integrated With DataProvenance (24)
- **Category**: Cross-reference inconsistencies
- **Location**: 12.5, 24.2
- **What's missing**: Spec 24 (provenance system) defines `DataProvenance` with fields like `source_context`, `source_type`, `chain_depth`, `chain_path`. Spec 12 defines `BridgeProvenance` as an extension. The implementation wraps `DataProvenance` inside `BridgeProvenance`. However, spec 24 never references `BridgeProvenance` or defines how bridge provenance integrates with the quality evaluation in 24.5. Does bridged content go through the same `evaluate_quality` pipeline? What `SourceType` does bridged content have?
- **Why it matters**: Two provenance systems that don't interoperate create confusion. The quality evaluation in 24.5.1 (mapping source context state to ProvenanceQuality tier) doesn't account for bridge-originated content at all.
- **Severity**: HIGH

### [12.10.2-001] JWT Signing Algorithm Not Specified
- **Category**: Missing wire format details
- **Location**: 12.10.2
- **What's missing**: The authentication section says "DID-signed bearer tokens" using JWT but does not specify the signing algorithm. Given the protocol uses Ed25519 everywhere, this should be `EdDSA` (RFC 8037), but the spec doesn't say. JWT `alg` header value is not specified.
- **Why it matters**: Without an explicit algorithm, implementations may use different JWT signing algorithms, producing incompatible tokens.
- **Severity**: MEDIUM

### [12.10.2-002] JWT Token Lifetime "SHOULD NOT exceed 1 hour" is Soft
- **Category**: Vague requirements
- **Location**: 12.10.2
- **What's missing**: "Token lifetime SHOULD NOT exceed 1 hour" -- SHOULD NOT is advisory per RFC 2119. There is no maximum (MUST NOT exceed), no recommended default, and no specification of what platforms should do with tokens that exceed this. Accept with warning? Reject?
- **Why it matters**: Without a hard maximum, a bridge could issue tokens valid for years, creating a long-lived credential that survives bridge revocation.
- **Severity**: MEDIUM

### [12.10.2-003] DID Document Cache TTL Not Specified for Platform Verification
- **Category**: Missing constants/defaults
- **Location**: 12.10.2
- **What's missing**: "The platform MAY cache resolved DID documents with TTL." No default TTL specified. A platform that caches indefinitely would not detect DID key rotation. A platform that never caches would DDoS the DHT.
- **Why it matters**: DID document caching directly impacts key rotation security. If a bridge operator rotates their key (compromise recovery), the platform must resolve the new key within a bounded time.
- **Severity**: MEDIUM

### [12.10.2-004] Webhook Signature Scheme Underspecified
- **Category**: Missing wire format details
- **Location**: 12.10.2
- **What's missing**: Webhook callbacks use `X-SCP-Signature: <Ed25519 signature over raw request body>`. This is ambiguous: is the signature over the raw bytes of the request body (before or after encoding)? Is there a domain separator? Is Content-Encoding considered? Is there a timestamp to prevent replay?
- **Why it matters**: Without a canonical serialization of the signed content and replay protection (timestamp or nonce), webhook signatures are replayable. An attacker who intercepts one webhook delivery can replay it indefinitely.
- **Severity**: HIGH

### [12.10.2-005] Platform Key Registration Mechanism Unspecified
- **Category**: Underspecified algorithms
- **Location**: 12.10.2
- **What's missing**: "The bridge node verifies the signature against the platform's pre-registered public key (exchanged during bridge registration)." How is this key exchanged? During what registration step? Is it a DID? A raw public key? A certificate?
- **Why it matters**: Key exchange is a fundamental trust establishment step. Without specifying the mechanism, implementations must invent their own, which may be insecure.
- **Severity**: HIGH

### [12.10.3-001] Error Code Registry Not Extensible
- **Category**: Missing conformance criteria
- **Location**: 12.10.3
- **What's missing**: Nine error codes are defined. No mechanism for platforms to define custom error codes. No specification of how unknown error codes should be handled by bridge nodes.
- **Why it matters**: Platforms will have platform-specific error conditions. Without extensibility, they must map everything to `INTERNAL_ERROR` (500), losing diagnostic information.
- **Severity**: LOW

### [12.10.3-002] Rate Limit Values Not Specified
- **Category**: Missing constants/defaults
- **Location**: 12.10.3
- **What's missing**: "Rate limiting uses standard Retry-After headers (seconds). Limits are platform-configurable." The status endpoint example shows `messages_per_minute: 60` and `shadows_per_hour: 100` but these are example values. No protocol-recommended defaults. No specification of what happens when rate limits change mid-session.
- **Why it matters**: Without recommended defaults, platforms may set absurdly low limits (1 message per hour) that effectively break bridging while appearing compliant.
- **Severity**: LOW

### [12.10.4-001] POST /v1/scp/bridge/message Content Size Limit Unspecified
- **Category**: Missing constants/defaults
- **Location**: 12.10.4
- **What's missing**: The message endpoint accepts a `content` string field. No maximum content size is specified. No reference to the relay's `max_blob_size` (default 256KB per 10).
- **Why it matters**: A cooperating platform could send a 1GB message body, causing the bridge node to attempt MLS encryption on enormous payloads. This is a denial-of-service vector.
- **Severity**: HIGH

### [12.10.4-002] POST /v1/scp/bridge/message Content Types Not Enumerated
- **Category**: Vague requirements
- **Location**: 12.10.4
- **What's missing**: `content_type` is documented as `"text/plain", "text/markdown", "application/json"` but this list appears to be illustrative, not exhaustive. Can a platform send `"image/png"` with binary content? `"application/octet-stream"`? Is the `content` field always UTF-8 string, or can it be binary?
- **Why it matters**: If `content` is always a JSON string, binary content must be base64-encoded. This is not stated. If it can be binary, the JSON payload structure needs to handle it differently.
- **Severity**: MEDIUM

### [12.10.4-003] POST /v1/scp/bridge/message Deduplication By platform_message_id Not Specified
- **Category**: Underspecified algorithms
- **Location**: 12.10.4
- **What's missing**: `platform_message_id` is described as "for deduplication and cross-reference" but the deduplication behavior is not specified. Does the bridge node deduplicate? Does the SCP context deduplicate? Over what time window? What happens if the same `platform_message_id` is sent with different content?
- **Why it matters**: Without specified deduplication semantics, platforms that retry on timeout may produce duplicate messages in the SCP context.
- **Severity**: MEDIUM

### [12.10.4-004] POST /v1/scp/bridge/attest Attestation Expiry Default Not Binding
- **Category**: Vague requirements
- **Location**: 12.10.4
- **What's missing**: "Attestation expiry defaults to 24 hours; the platform MAY request a different TTL." How does the platform request a different TTL? There is no `ttl` field in the request body. No minimum or maximum TTL is specified. A platform could set TTL to 10 years.
- **Why it matters**: Attestation TTL controls how long the identity mapping is considered valid. An excessively long TTL means stale attestations persist, potentially allowing identity confusion after platform account changes.
- **Severity**: MEDIUM

### [12.10.4-005] POST /v1/scp/bridge/attest No Refresh/Renewal Mechanism
- **Category**: Missing edge cases
- **Location**: 12.10.4
- **What's missing**: Attestations expire after 24 hours by default. There is no renewal endpoint. The platform must re-attest from scratch each time. No specification of what happens to shadow trust levels when attestation expires but shadow is still active.
- **Why it matters**: Without renewal, every platform must implement re-attestation polling. Expired attestations that are not renewed may silently degrade shadow trust without notification.
- **Severity**: LOW

### [12.10.4-006] GET /v1/scp/bridge/status Pagination Not Specified
- **Category**: Underspecified algorithms
- **Location**: 12.10.4
- **What's missing**: "The array MAY be paginated for large rosters using standard Link headers with rel='next'." Page size is not specified. Cursor format is not specified. Whether the cursor is opaque or transparent is not specified. Sorting order is not specified.
- **Why it matters**: Without pagination specification, large rosters (thousands of shadows) may be returned in full, causing response payloads that exceed platform memory.
- **Severity**: LOW

### [12.10.4-007] DELETE /v1/scp/bridge/shadow/{shadow_id} No Authorization Check Specified
- **Category**: Security-relevant omissions
- **Location**: 12.10.4
- **What's missing**: The delete endpoint description says "the bridge operator" can delete shadows. But the authorization model only checks the bearer token (which proves the request comes from the bridge operator's DID). There is no specification of whether the bridge operator can delete shadows created by a different bridge in the same context. The implementation in `registration.rs` scopes by context but not by bridge instance.
- **Why it matters**: If shadow deletion is not scoped to the bridge that created the shadow, a malicious bridge operator could delete other bridges' shadows.
- **Severity**: MEDIUM

### [12.10.4-008] POST /v1/scp/bridge/webhook Event Deduplication Window Not Specified
- **Category**: Missing constants/defaults
- **Location**: 12.10.4
- **What's missing**: "The bridge node deduplicates by event_id." No specification of the deduplication window. How long must the bridge node remember seen event IDs? 1 hour? 24 hours? Forever? Memory implications differ dramatically.
- **Why it matters**: Without a defined deduplication window, implementations may either consume unbounded memory (forever) or allow replays (too short).
- **Severity**: MEDIUM

### [12.10.4-009] POST /v1/scp/bridge/webhook message_edit and message_delete Semantics Incomplete
- **Category**: Missing edge cases
- **Location**: 12.10.4
- **What's missing**: `message_edit` webhook provides `platform_message_id`, `new_content`, `new_content_type`, `edited_at`. But SCP messages, once constructed into MLS envelopes and published to the relay, cannot be edited (they are in a Merkle-logged event stream). How does a message edit from an external platform translate to the immutable SCP context? Is it a new message with a reference to the original? A governance action?
- **Why it matters**: This is a fundamental semantic mismatch between mutable external platforms and immutable SCP event logs. Without resolution, message edits would be silently dropped or produce inconsistent state.
- **Severity**: HIGH

### [12.10.4-010] POST /v1/scp/bridge/webhook No Content Size Limit on Payload
- **Category**: Missing constants/defaults
- **Location**: 12.10.4
- **What's missing**: The webhook payload has no specified maximum size. A malicious or misconfigured platform could send a webhook with a 1GB `content` field, causing the bridge node to OOM.
- **Why it matters**: DoS via oversized webhook payloads. The bridge node's 5-second response timeout doesn't protect against payloads that exceed memory before processing begins.
- **Severity**: MEDIUM

### [12.10.4-011] SCP-to-Platform Message Flow Entirely Unspecified
- **Category**: Underspecified algorithms
- **Location**: 12.10.5
- **What's missing**: 12.10.5 mentions "SCP-to-platform: the bridge node receives SCP messages and calls platform APIs to deliver them" but there is no specification of this flow. No endpoint is defined for the bridge node to push messages to the platform. No format. No error handling. The entire outbound direction is hand-waved.
- **Why it matters**: A bridge that can only relay platform-to-SCP but not SCP-to-platform is a one-way mirror, not a bridge. The bidirectional claim is unsupported by the spec.
- **Severity**: HIGH

### [12.10.5-001] Bridge Node Registration Wire Protocol Not Specified
- **Category**: Missing wire format details
- **Location**: 12.10.5
- **What's missing**: "The bridge operator registers the bridge with an SCP context via register_bridge() (12.2). The registration includes the platform's webhook URL and authentication credentials." Neither register_bridge() nor its parameters are defined in any spec section. What is the wire format? What governance action approves it? How is the webhook URL communicated?
- **Why it matters**: This is the fundamental bootstrap operation for bridge connectivity and it has no protocol specification.
- **Severity**: HIGH

### [12.10.7-001] Partial Implementation Conformance Not Specified
- **Category**: Missing conformance criteria
- **Location**: 12.10.7
- **What's missing**: "The platform MAY implement a subset of endpoints. At minimum, shadow creation and the message webhook enable basic participation." But there are no conformance levels defined. What is "Level 1" (shadows + messages)? What is "Level 2" (+ attestation)? What is "full conformance"? Without levels, implementations can't declare what they support.
- **Why it matters**: Conformance levels enable interoperability testing and capability negotiation. Without them, each platform is a unique snowflake.
- **Severity**: LOW

### [12.11.1-001] Credential Encryption Key Derivation Not Specified
- **Category**: Underspecified algorithms
- **Location**: 12.11.2
- **What's missing**: "Credentials MUST be encrypted using a key derived from the bridge operator's identity key material (e.g., HKDF from the operator's signing key with a bridge-specific salt)." The "(e.g., HKDF...)" is illustrative, not normative. No specific KDF is mandated. No salt derivation is specified. No info string for domain separation.
- **Why it matters**: If implementations use different KDFs or salts, credential portability between bridge implementations is impossible. More importantly, without a specified construction, implementations may use weak key derivation.
- **Severity**: HIGH

### [12.11.1-002] Credential Destruction Verification Impossible
- **Category**: Missing conformance criteria
- **Location**: 12.11.2
- **What's missing**: "Destruction means: (a) call the platform's revocation endpoint if one exists, (b) overwrite local credential material with zeros, (c) delete the credential record." There is no mechanism to verify that a bridge implementation has actually destroyed credentials. No attestation. No audit log entry. No conformance test.
- **Why it matters**: A malicious bridge operator can claim to have destroyed credentials while retaining a copy. The spec mandates destruction but provides no verification mechanism.
- **Severity**: MEDIUM

### [12.11.3-001] OAuth PKCE Code Verifier Length Not Specified
- **Category**: Missing constants/defaults
- **Location**: 12.11.3
- **What's missing**: The OAuth reference binding specifies PKCE with S256 but does not specify the code verifier length. RFC 7636 allows 43-128 characters. The spec should mandate a minimum for security.
- **Why it matters**: Short code verifiers are brute-forceable. Production OAuth implementations should use at least 43 characters of high-entropy random data.
- **Severity**: LOW

### [12.11.3-002] OAuth Token Storage Encryption Specification Missing
- **Category**: Underspecified algorithms
- **Location**: 12.11.3
- **What's missing**: "Both are encrypted at rest using a key derived from the operator's identity key material." Same issue as 12.11.1-001 -- the encryption algorithm (AES-256-GCM? ChaCha20-Poly1305?) is not specified, just the key derivation vaguely.
- **Why it matters**: Without specifying the encryption algorithm, implementations may use weak encryption (e.g., AES-ECB) for credential storage.
- **Severity**: MEDIUM

### [12.11.3-003] Refresh Token Failure Degraded State Undefined
- **Category**: Undefined error/failure behavior
- **Location**: 12.11.3
- **What's missing**: "If refresh fails after all retries (e.g., refresh token revoked by the platform), transition the bridge to a degraded state." What is "degraded state"? It is not one of the three `BridgeStatus` values (Active, Suspended, Revoked). Is this a new state? A sub-state of Active? How do context members learn the bridge is degraded? What operations are allowed in degraded state?
- **Why it matters**: Undefined state introduces implementation divergence and potential security gaps (e.g., bridge continues operating on stale credentials in "degraded" mode).
- **Severity**: MEDIUM

### [12.6-001] Bridge MLS Membership Model Unspecified
- **Category**: Security-relevant omissions
- **Location**: 12.6
- **What's missing**: 12.6 says "Bridge connectors are not agents -- they cannot initiate actions, exercise capabilities, or participate in governance." But the bridge node must be able to publish messages to the SCP context (it constructs envelopes and publishes them). This requires either: (a) the bridge operator to be a context member with MLS keys, or (b) some special bridge-specific enrollment mechanism. Neither is specified.
- **Why it matters**: This is a fundamental architectural question. If the bridge operator is an MLS group member, they can decrypt all messages in the context. If they're not, they need a mechanism to submit messages to the group. Neither path is specified.
- **Severity**: CRITICAL

### [12.6-002] Bridge Connector Encryption Access Model Unspecified
- **Category**: Security-relevant omissions
- **Location**: 12.6
- **What's missing**: In encrypted contexts (ContextMode::Encrypted), messages are MLS-encrypted. The bridge node needs to read decrypted SCP messages to relay them to external platforms (SCP-to-platform flow) and write encrypted messages for platform-to-SCP flow. How does the bridge access encryption keys? Is the bridge operator part of the MLS group? If so, the bridge operator can read ALL messages, not just bridged ones. If not, how does the bridge encrypt outbound messages?
- **Why it matters**: This determines whether bridge connectors are compatible with encrypted contexts at all. If the bridge operator must be in the MLS group, every bridge operator can read all context messages -- a massive privacy concern. The spec is completely silent on this.
- **Severity**: CRITICAL

### [12.7-001] Self-Hosted Bridge Discovery Mechanism Not Specified
- **Category**: Underspecified algorithms
- **Location**: 12.7
- **What's missing**: "A user can run their own bridge to connect their own external platform accounts into SCP contexts they participate in." How does a self-hosted bridge register with a context? Does it use the same registration flow as managed bridges? How does the context know the bridge is self-hosted (trust implication)?
- **Why it matters**: Self-hosted bridges have different trust properties (user controls their own credentials). The protocol should distinguish them for trust evaluation purposes.
- **Severity**: LOW

### [12-METADATA-001] Bridge Presence Not Listed in Context Metadata (5.7)
- **Category**: Cross-reference inconsistencies
- **Location**: 12.2, 5.7
- **What's missing**: 12.2 says "Bridge presence, operator identity, connected platform, and operating mode are visible to all context members and in context metadata (visible before opt-in)." However, 5.7 (Context Metadata) does NOT list bridge information in the metadata visible before opt-in. Active bridges, their operators, platforms, and modes are not mentioned in the metadata list.
- **Why it matters**: The legibility tenet requires bridge information to be visible before joining. If it's not in 5.7's metadata definition, implementations may omit it from pre-join metadata, violating the legibility commitment.
- **Severity**: HIGH

### [12-PROVENANCE-001] Bridge Provenance Integration With Merkle Log Not Specified
- **Category**: Missing wire format details
- **Location**: 12.5
- **What's missing**: 12.5 says "provenance is structural, not content-level. It flows through the data provenance system (7.7)." But how does bridge provenance get recorded in the context's Merkle log? Is `BridgeProvenance` a field on the event log entry? A separate linked record? The implementation has `mark_bridge_provenance()` but no integration with event log serialization.
- **Why it matters**: Without specifying the storage format, provenance data may not survive event log export/import or cross-implementation sync.
- **Severity**: MEDIUM

### [12-CAPABILITY-001] "bridging" Capability Ceiling Category Not Detailed
- **Category**: Underspecified algorithms
- **Location**: 12, 5.3
- **What's missing**: 5.3 lists `bridging` as a capability ceiling category meaning "bridge connector participation (12)." But the spec never defines what operations fall under this capability. Does `bridging` gate: bridge registration? shadow creation? message relay through bridge? All of the above? Can bridging be partially enabled (e.g., allow bridge registration but not shadow creation)?
- **Why it matters**: Capability ceiling is the primary security boundary for contexts. Without defining what `bridging` encompasses, contexts cannot make informed capability decisions.
- **Severity**: MEDIUM

### [12-SECURITY-001] Malicious Bridge Operator Threat Model Incomplete
- **Category**: Security-relevant omissions
- **Location**: 12
- **What's missing**: Section 9.2 (threat vectors) does not include bridge-specific threats. A malicious bridge operator can: (a) fabricate shadow identities that don't correspond to real external users, (b) attribute messages to shadows that the external user never sent, (c) modify content in transit (relay/puppet modes), (d) forge platform timestamps, (e) refuse to relay SCP-to-platform messages while appearing active. None of these are addressed.
- **Why it matters**: Bridge operators are explicitly trusted intermediaries. The threat model should enumerate what a malicious bridge operator can do and what the protocol's mitigations are. Currently, the answer is: a malicious operator can fabricate arbitrary content attributed to arbitrary external identities, and the only defense is operator DID accountability after the fact.
- **Severity**: CRITICAL

### [12-SECURITY-002] No Mechanism to Verify External Platform Identity Claims
- **Category**: Security-relevant omissions
- **Location**: 12.3, 12.10.4 (attest)
- **What's missing**: The attest endpoint lets a platform "vouch for a user's identity" but there is no protocol-level mechanism for verifying that the platform's attestation is truthful. The platform is trusted entirely based on the bridge operator's DID. A cooperating platform could fabricate attestations for users who don't exist on the platform.
- **Why it matters**: The trust hierarchy assumes platform attestations are meaningful. Without verification, a malicious cooperating platform is indistinguishable from a legitimate one.
- **Severity**: MEDIUM

---

## Spec 13: Versioning and Protocol Evolution (12 findings)

### [13-001] No Protocol Version Number Defined
- **Category**: Missing constants/defaults
- **Location**: 13
- **What's missing**: The spec discusses semantic versioning but never declares what the current protocol version is. Is it 0.1? 1.0? Pre-release? Section 18 (addressability) references `version: 1` in the well-known endpoint, but this is the only concrete reference. Spec 13 should be the canonical source for the current version and it says nothing.
- **Why it matters**: Without a declared version, capability negotiation (13, bullet 2) cannot function. Agents cannot declare what version they support if no version exists.
- **Severity**: HIGH

### [13-002] Version Negotiation Protocol Not Specified
- **Category**: Underspecified algorithms
- **Location**: 13
- **What's missing**: "Agents and contexts declare which protocol version they support." How? In what field? In what message? "Contexts can set minimum version requirements for participation." Where is this declared? In context metadata (5.7)? In the MLS welcome message? In the capability ceiling? None of this is specified.
- **Why it matters**: Version negotiation is fundamental to protocol evolution. Without a specified mechanism, it cannot be implemented.
- **Severity**: CRITICAL

### [13-003] Forward Compatibility Rules Not Specified
- **Category**: Underspecified algorithms
- **Location**: 13
- **What's missing**: "New protocol versions must define how old agents interact with new features -- graceful degradation, not hard failure." This is a design principle, not a specification. No rules for how unknown fields are handled. No specification of whether unknown message types are ignored, queued, or rejected. No TLV or extension mechanism defined.
- **Why it matters**: Without forward compatibility rules, the first version bump will break all existing clients. The spec should define at minimum: (a) unknown fields in serialized objects are preserved but ignored, (b) unknown message types produce a defined error, (c) extensions use a defined namespace.
- **Severity**: HIGH

### [13-004] Extension Point Registration Mechanism Not Specified
- **Category**: Underspecified algorithms
- **Location**: 13
- **What's missing**: "The attestation type system, tool schema format, and capability declaration contract are designed to be extensible without protocol version bumps." But no extension point registry exists. No namespacing for extensions. No mechanism to register new attestation types without collision. No specification of how an agent discovers that an extension is in use.
- **Why it matters**: Without a registry or namespacing, two independent extensions could use the same attestation type name with different semantics, causing silent data corruption.
- **Severity**: HIGH

### [13-005] No Breaking Change Definition
- **Category**: Missing conformance criteria
- **Location**: 13
- **What's missing**: "Breaking changes increment the major version." What constitutes a breaking change? Adding a required field? Changing a field type? Removing a field? Changing the semantics of an existing field? Without a definition, the boundary between minor version bump and major version bump is subjective.
- **Why it matters**: Protocol stability depends on a shared understanding of what changes are breaking. Different implementations may disagree on what triggers a version bump.
- **Severity**: MEDIUM

### [13-006] No Deprecation Mechanism
- **Category**: Missing edge cases
- **Location**: 13
- **What's missing**: No mechanism for deprecating features across versions. No sunset timeline. No deprecation warning in protocol messages. No specification of how long old versions must be supported.
- **Why it matters**: Without deprecation, the protocol accumulates dead weight forever. With deprecation but without a mechanism, implementations drop features unilaterally.
- **Severity**: MEDIUM

### [13-007] No Feature Discovery or Capability Advertisement
- **Category**: Underspecified algorithms
- **Location**: 13
- **What's missing**: Extensions can be added without version bumps, but there is no mechanism for an agent to discover what extensions a context supports. No feature flags. No capability advertisement beyond the version number.
- **Why it matters**: An agent cannot know whether a context supports a particular extension without trial and error.
- **Severity**: MEDIUM

### [13-008] "Degraded Mode" Participation Not Specified
- **Category**: Ambiguous state transitions
- **Location**: 13
- **What's missing**: "Agents encountering a context with a higher version than they support can decline to join or participate in a degraded mode." What is degraded mode? What operations are available? What operations are blocked? How does the agent know which features are version-gated?
- **Why it matters**: Degraded mode is a critical interoperability mechanism. Without specification, implementations will either refuse to join (too conservative) or join and break (too permissive).
- **Severity**: HIGH

### [13-009] No Version in Wire Format
- **Category**: Missing wire format details
- **Location**: 13
- **What's missing**: The spec mentions semantic versioning but never specifies where the version appears in wire messages. MLS has its own protocol version. SCP envelope construction does not include a protocol version field. Without a version in every message, receivers cannot detect version mismatches.
- **Why it matters**: Version detection at the message level is necessary for forward compatibility and graceful degradation.
- **Severity**: HIGH

### [13-010] No Migration Tooling Specification
- **Category**: Missing edge cases
- **Location**: 13
- **What's missing**: When a breaking change occurs (major version bump), how do existing contexts migrate? Do they? Or are they abandoned? The spec says the goal is that "existing contexts and agents continue to work" but provides no mechanism for how.
- **Why it matters**: Major version bumps without migration paths fracture the network. This contradicts the principle stated in CLAUDE.md: "No migration paths. Don't ship into something you plan to abandon."
- **Severity**: MEDIUM

### [13-011] Extension Collision Resolution Not Addressed
- **Category**: Missing edge cases
- **Location**: 13
- **What's missing**: If two independent developers create extensions with the same attestation type name, there is no collision detection or resolution mechanism. No namespacing. No registry.
- **Why it matters**: Extension collisions cause silent data misinterpretation, which in a security protocol can lead to incorrect trust evaluation.
- **Severity**: MEDIUM

### [13-012] No Conformance Test Framework Referenced
- **Category**: Missing conformance criteria
- **Location**: 13
- **What's missing**: No reference to a conformance test suite or test vectors that would verify protocol version compatibility. Spec 16 (test infrastructure) exists but 13 doesn't reference it for version conformance testing.
- **Why it matters**: Without conformance tests, version compatibility claims are untestable.
- **Severity**: LOW

---

## Spec 14: Protocol Governance (5 findings)

### [14-001] No Governance Transition Triggers Specified
- **Category**: Underspecified algorithms
- **Location**: 14
- **What's missing**: Three stages are described (early, growth, mature) with no criteria for transitioning between them. What adoption metrics trigger the transition? Who decides? What is the mechanism for broadening governance? The spec says "as adoption grows" but provides no threshold or process.
- **Why it matters**: Without transition criteria, the protocol governance may never leave the "early stage" (Limn controls everything) regardless of adoption. This creates a centralization risk that contradicts the self-sovereignty ethos.
- **Severity**: MEDIUM

### [14-002] No Foundation Structure Specified
- **Category**: Underspecified algorithms
- **Location**: 14
- **What's missing**: "A foundation or equivalent governance body stewards the specification." No specification of: foundation charter, voting mechanism, contribution criteria, IP licensing model, decision-making process, conflict resolution, or membership criteria.
- **Why it matters**: Foundation formation without prior specification leads to ad hoc governance that may not serve the community. Matrix.org Foundation and W3C both had governance structures documented before formation.
- **Severity**: LOW

### [14-003] No Process for Protocol-Level Governance Decisions
- **Category**: Underspecified algorithms
- **Location**: 14
- **What's missing**: The spec says "protocol-level governance decisions are rare" but provides no process for when they do occur. No RFC process. No consensus mechanism. No voting structure. No dispute resolution. How is a protocol change proposed, reviewed, and accepted?
- **Why it matters**: Without a change process, protocol evolution defaults to whoever controls the reference implementation.
- **Severity**: MEDIUM

### [14-004] No IP/Patent Policy
- **Category**: Missing edge cases
- **Location**: 14
- **What's missing**: No specification of intellectual property policy. No patent non-assertion pledge. No contributor license agreement. No specification of whether protocol extensions must be royalty-free.
- **Why it matters**: IP ambiguity discourages adoption. Enterprise users need IP clarity before committing to a protocol. IETF has the Note Well, W3C has the Patent Policy. SCP has nothing.
- **Severity**: MEDIUM

### [14-005] Relationship to Code Governance Undefined
- **Category**: Cross-reference inconsistencies
- **Location**: 14
- **What's missing**: Protocol governance and reference implementation governance are conflated. The spec doesn't distinguish between: (a) changes to the protocol specification, (b) changes to the reference implementation, (c) changes to the SDK. These have different stakeholders and different governance needs.
- **Why it matters**: A change to the SDK that doesn't change the protocol should not require protocol-level governance. Without separation, all changes become protocol governance decisions, creating a bottleneck.
- **Severity**: LOW

---

## Spec 15: Regulatory Compliance (3 findings)

### [15-001] Right to Erasure Content Handling Contradicts Merkle Integrity
- **Category**: Cross-reference inconsistencies
- **Location**: 15
- **What's missing**: "Content they authored in contexts remains (attributed to a now-revoked DID)." But context event logs are Merkle trees (7.3.1). Removing content from a Merkle tree invalidates all subsequent hashes. The spec acknowledges the protocol "does not retroactively delete content" but doesn't address the tension between GDPR erasure requests and Merkle tree integrity. No specification of: (a) how to handle a legally-mandated erasure request, (b) whether "tombstoning" (replacing content with a tombstone record while preserving the Merkle structure) is supported, (c) whether erasure applies to the content or just the identity link.
- **Why it matters**: EU GDPR Article 17 grants the right to erasure. SCP's architecture makes erasure structurally impossible for content in shared contexts. The spec hand-waves this with "apps and context governance can implement content deletion policies" without addressing the Merkle integrity constraint. A legally-mandated erasure request against a Merkle-logged context has no specified resolution.
- **Severity**: CRITICAL

### [15-002] Relay Operator Legal Classification Not Addressed
- **Category**: Vague requirements
- **Location**: 15
- **What's missing**: "Relays handle opaque encrypted blobs and are not positioned to be classified as content intermediaries... This legal argument has not been tested in any jurisdiction." The spec admits the legal position is untested but then says "the protocol's design assumes it." This is a compliance gap, not a design decision. No guidance on: (a) what legal counsel relay operators should seek, (b) what jurisdictional variations exist (EU DSA, US Section 230, etc.), (c) what happens if a court classifies relays as content intermediaries.
- **Why it matters**: Relay operators accepting this spec's assurance face unquantified legal risk. The spec should at minimum provide a risk analysis and note that relay operators must seek jurisdiction-specific legal counsel.
- **Severity**: MEDIUM

### [15-003] Data Subject Access Request (DSAR) Mechanism Not Specified
- **Category**: Security-relevant omissions
- **Location**: 15
- **What's missing**: GDPR grants data subjects the right to access their personal data (Article 15). The spec discusses erasure and portability but not access requests. How does a user request all data held about them? The decentralized architecture means data is spread across multiple contexts and relays. No specification of: (a) what constitutes a complete response to a DSAR, (b) how to aggregate data across contexts, (c) the timeline for response (GDPR: 1 month).
- **Why it matters**: DSAR compliance is a legal requirement for any entity processing personal data of EU residents. Without a mechanism, SCP operators have no way to comply.
- **Severity**: MEDIUM

---

## Cross-Cutting Findings

### [CROSS-001] Spec 12 Open Questions Self-Contradicted
- **Category**: Cross-reference inconsistencies
- **Location**: 00-open-questions.md line 17
- **What's missing**: Open question "Bridge connector interface specification" is marked as "Still open -- needs design work" and classified as P3. However, 12.10 and 12.11 were subsequently added, providing the cooperative mode HTTP binding and credential lifecycle. The open question was never updated to reflect this partial resolution.
- **Why it matters**: Stale open questions create confusion about what is and isn't specified. The open question should be updated to note that cooperative mode binding is resolved and only relay/puppet/API mode interfaces remain open.
- **Severity**: LOW

### [CROSS-002] Spec 12 Bridge Credential Open Question Self-Contradicted
- **Category**: Cross-reference inconsistencies
- **Location**: 00-open-questions.md line 18
- **What's missing**: Open question "Bridge credential custody" is marked as "Still open -- needs design work" and classified as P4. However, 12.11 was subsequently added, providing the credential lifecycle specification. The open question was never updated.
- **Why it matters**: Same as CROSS-001. Stale open questions.
- **Severity**: LOW
