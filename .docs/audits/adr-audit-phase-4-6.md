---

# ADR Unspecified Details Audit: Phase 4, Phase 5, Phase 6

## Executive Summary

This audit covers 14 ADRs across three phase files (ADR-017 through ADR-022, ADR-023 through ADR-026, ADR-027 through ADR-031, ADR-034, ADR-038, ADR-041). The ADRs are well-structured and more thorough than most I review -- they include code examples, acceptance criteria, rationale, and dependency mapping. That said, thoroughness is not completeness. I found **53 findings** ranging from critical cryptographic errors to missing defaults, including 6 CRITICAL, 14 HIGH, 22 MEDIUM, and 11 LOW severity issues.

The most concerning patterns are: (1) a cryptographic construction error in ADR-027's storage key derivation that uses AES-GCM with a fixed IV, (2) multiple places where `f64` is used for comparison-critical types that need `Eq` derivation, (3) the WASM re-implementation strategy (ADR-034) that structurally undermines the "one implementation" security invariant, and (4) several wire protocol types missing anti-replay or size-bound protections. The governance ADR (031) is the most complete and well-reasoned of the set; the trust engine ADR (017) is the thinnest.

---

## Critical Findings

### [ADR-027] C1: AES-GCM with Fixed IV for Storage Key Derivation
- **Category**: Missing security analysis
- **Location**: ADR-027, `AndroidStorage.kt` code block, line ~302-307
- **What's missing**: The `getOrCreateStorageKey()` function uses `GCMParameterSpec(128, ByteArray(12))` -- a 12-byte all-zero IV -- with a comment "fixed IV for determinism." AES-GCM's security model requires that no (key, nonce) pair is ever reused. While this particular usage encrypts a fixed label with a fixed key, meaning only one encryption ever occurs per key, this is not stated or enforced. If the function is ever called more than once with the same Keystore key (e.g., after database deletion and recreation, or during migration), the IV reuse leaks information via XOR of ciphertexts. More fundamentally, using AES-GCM for key derivation is the wrong primitive -- HKDF or a simple HMAC-SHA256 KDF would be correct here.
- **Why it matters**: A deterministic AES-GCM encryption is a misuse of the primitive even if it accidentally works for one invocation. It sets a dangerous pattern, and the "determinism" requirement can be satisfied safely with HKDF.
- **Severity**: CRITICAL

### [ADR-034] C2: WASM Re-Implementation Fundamentally Contradicts Security Model
- **Category**: Contradictions with other ADRs
- **Location**: ADR-034, entire decision
- **What's missing**: ADR-034 explicitly states the WASM bridge is a "verbatim re-implementation" and "NOT a fork -- it is a second implementation of the same specification." This directly contradicts the foundational invariant from ADR-013/021/022 that there is "one implementation" of every protocol operation. The conformance test mitigation is necessary but insufficient -- conformance tests verify happy-path equivalence, not security-property equivalence. A second implementation of MLS, sender keys, UCAN validation, and the access key layer has a high probability of introducing subtle differences in error handling, timing, cryptographic edge cases, and state management that conformance tests will not catch.
- **Why it matters**: Two independent implementations of a cryptographic protocol have historically been the source of critical vulnerabilities (see: every TLS implementation divergence CVE). The ADR acknowledges drift risk but treats it as an operational problem solvable with checklists. It is a security problem.
- **Severity**: CRITICAL

### [ADR-029] C3: ResetRequest Sent Without MLS Encryption -- No Anti-Replay
- **Category**: Missing security analysis
- **Location**: ADR-029, section 4, `ResetRequest` struct definition
- **What's missing**: `ResetRequest` is sent "not MLS-encrypted -- the member may not be able to encrypt at the current epoch." The request contains `context_id`, `member_did`, `last_known_epoch`, `reason`, `timestamp`, and a `signature`. There is no nonce, no challenge-response, and no relay-provided freshness binding. A relay that observes a signed `ResetRequest` can replay it at any future time to force-reset a member who has since caught up. The timestamp provides no protection because the clock is self-reported and the ADR does not specify a freshness window.
- **Why it matters**: A malicious relay can weaponize observed `ResetRequest` messages to repeatedly force-reset members, causing them to lose access to messages encrypted between their last-known epoch and the current epoch. This is a targeted denial-of-service with data loss.
- **Severity**: CRITICAL

### [ADR-030] C4: EventTypeRetention Uses f64 -- Cannot Derive Eq, PartialEq Comparison Unsound
- **Category**: Contradictions with other ADRs / Incomplete decisions
- **Location**: ADR-030, section 2c, `EventTypeRetention` struct; also ADR-017 `ThresholdRequirement.independence_threshold: f64`
- **What's missing**: `EventTypeRetention` has two `f64` fields (`structural_retention_multiplier`, `operational_retention_multiplier`). These are embedded in `PruningPolicy`, which is embedded in `ContextStateSnapshot` (ADR-030 section 1), which must be deterministically serialized and hashed for checkpoint signatures. `f64` cannot derive `Eq` and its comparison semantics are unsound for security-critical equality checks (NaN != NaN, -0.0 == 0.0). The same issue exists in ADR-017 `ThresholdRequirement.independence_threshold: f64` and ADR-020 `DiscoveryResultEntry.relevance_score: f64`. Meanwhile, ADR-031 correctly uses `u32` basis points for `min_participation_bps` specifically to enable `Eq` derivation -- but the other ADRs do not follow this pattern.
- **Why it matters**: Deterministic serialization of `f64` values is platform-dependent (different CPUs may produce different bit patterns for the same computation). Checkpoint signature verification will fail across heterogeneous platforms, breaking the entire pruning/state-reconstruction system.
- **Severity**: CRITICAL

### [ADR-038] C5: Access Key Distribution After Full Revocation Has No Zeroization Confirmation
- **Category**: Missing security analysis
- **Location**: ADR-038, section 2 (Revocation Full)
- **What's missing**: Full revocation requires "all compliant SDKs delete the target's access key from their local key store." The ADR provides no mechanism for confirming deletion occurred. Non-compliant SDKs (or SDKs that crash before processing the deletion) retain the key indefinitely. There is no attestation, no confirmation event, and no audit mechanism. The entire security guarantee of Layer 3 depends on an unverifiable "SHOULD destroy" obligation. The contrast with key destruction attestation in ADR-018/025 (which acknowledges and records attestation levels) is notable -- ADR-038 does not even track whether deletion was attempted.
- **Why it matters**: The claim "historical wrapped CEKs for the target are permanently undecryptable" is conditional on universal deletion by all compliant clients. One retained copy on any client defeats the entire Layer 3 guarantee. Without confirmation, there is no way to distinguish "revocation effective" from "revocation unverifiable."
- **Severity**: CRITICAL

### [ADR-031] C6: UCAN Root Issuer Creates Unresolvable Trust Gap in Multi-Admin
- **Category**: Decisions without implementation guidance
- **Location**: ADR-031, section 6, "Root UCAN issuer"
- **What's missing**: The context creator remains the root UCAN issuer in all governance models, but the ADR claims "the creator cannot unilaterally mint capabilities that bypass governance." This is not enforced cryptographically -- it is an SDK-level policy. The creator holds the root signing key. If the creator's key is compromised (or if the creator is malicious), they can mint arbitrary UCANs that pass validation (the UCAN chain is valid from the root). The governance engine is bypassed because UCAN validation in ADR-016 validates the cryptographic chain, not governance approval. There is no mechanism to rotate or revoke the root UCAN issuer without creating a new context.
- **Why it matters**: In a Threshold(2-of-3) context, the creator can unilaterally escalate any member's capabilities by minting UCANs directly, bypassing the governance engine entirely. The governance model provides a false sense of distributed authority.
- **Severity**: CRITICAL

---

## High Findings

### [ADR-017] H1: Trust Engine Independence Score Algorithm Completely Unspecified
- **Category**: Decisions without implementation guidance
- **Location**: ADR-017, acceptance criterion 7, `check_threshold_attestation`
- **What's missing**: "Verifies independence: shared context memberships and mutual endorsements reduce independence score" -- but no algorithm is specified. How is independence scored? What is the formula? How are shared context memberships discovered (this requires cross-context information)? What weight does a mutual endorsement carry? This is the core of Sybil resistance in the trust model and it is completely hand-waved.
- **Why it matters**: Without a concrete algorithm, different implementations will compute different independence scores, making threshold attestation non-deterministic across clients.
- **Severity**: HIGH

### [ADR-017] H2: Challenge-Response Has No Anti-Replay Protection
- **Category**: Missing security analysis
- **Location**: ADR-017, `ChallengeRequest` and `ChallengeResponse` structs
- **What's missing**: `ChallengeResponse` contains a `challenge_id` and signature but no nonce or freshness binding. A relay that observes a valid challenge-response exchange can replay the response to fraudulently pass future challenges of the same type. The `completed_at` timestamp is self-reported.
- **Why it matters**: Challenge-response verification is used for capability attestation. Replay allows an agent to claim capabilities it demonstrated once but may no longer possess.
- **Severity**: HIGH

### [ADR-018] H3: Summary Verification Window Duration Unspecified
- **Category**: Missing defaults
- **Location**: ADR-018, acceptance criterion 6
- **What's missing**: "Open verification window (configurable, default defined per context)" -- but no default duration is specified. What is the default? 1 minute? 1 hour? 24 hours? The entire Summary memory scope depends on this window, and there is no value given.
- **Why it matters**: Without a default, implementations will choose different values, making Summary scope behavior non-deterministic across contexts.
- **Severity**: HIGH

### [ADR-019] H4: Provenance Chain Path Reveals Cross-Context Membership
- **Category**: Missing security analysis
- **Location**: ADR-019, `DataProvenance.chain_path: Option<Vec<ContextId>>`
- **What's missing**: `chain_path` records the ordered list of intermediary context IDs through which data flowed. This leaks cross-context relationship information to anyone who receives the data. If Alice is in contexts A, B, and C, and data flows A->B->C, the chain_path reveals that contexts A, B, and C are connected through shared membership. No threat analysis of this metadata leakage is provided.
- **Why it matters**: Context isolation is a core security boundary. Chain paths create an observable graph of context relationships that an adversary can use for traffic analysis.
- **Severity**: HIGH

### [ADR-020] H5: Discovery Reader Authentication Not Specified
- **Category**: Underspecified interfaces
- **Location**: ADR-020, acceptance criterion 4-5
- **What's missing**: "Reader tier: DID-authenticated, unbounded, query via tool endpoints without MLS join." How is DID authentication performed for readers who are not MLS group members? The ADR says "DID-signed request" but does not specify the authentication protocol -- is it a signed HTTP request? A signed SCP message? What prevents replay of a valid DID-signed query?
- **Why it matters**: Unauthenticated or replay-vulnerable reader queries could be used to enumerate all entries in a context with discovery tools.
- **Severity**: HIGH

### [ADR-021] H6: Tokio Runtime Shutdown Grace Period May Lose Crypto State
- **Category**: Scope gaps
- **Location**: ADR-021, acceptance criterion 1
- **What's missing**: "Runtime shutdown occurs on library unload with a 5-second grace period for in-flight tasks." MLS group operations (Commit processing, key export, epoch ratcheting) can take longer than 5 seconds on mobile hardware. If the runtime shuts down during an MLS operation, the group state may be left in an inconsistent state (partial Commit application). No guidance on what happens to in-flight crypto operations.
- **Why it matters**: Inconsistent MLS group state after forced runtime shutdown could make a context unrecoverable.
- **Severity**: HIGH

### [ADR-022] H7: WASM Bridge Uses RefCell/Arc<Mutex> for Opaque Handles -- Thread Safety Unanalyzed
- **Category**: Missing security analysis
- **Location**: ADR-022, wasm-bindgen bridge description
- **What's missing**: "Opaque handles (`WasmIdentity`, `WasmContextHandle`) are annotated `#[wasm_bindgen]` structs holding Rust state behind a `RefCell` or `Arc<Mutex<...>>`." `RefCell` is not `Send`/`Sync` and will panic on concurrent access. WASM is single-threaded today but SharedArrayBuffer + Atomics enable multi-threaded WASM. The ADR does not analyze which choice is made or why, nor does it specify the behavior if a handle is accessed from multiple threads.
- **Why it matters**: `RefCell` panic on concurrent access would manifest as an unrecoverable runtime error in the browser with no actionable error message.
- **Severity**: HIGH

### [ADR-025] H8: App Attest clientDataJSON Field Ordering Is Specified But Fragile
- **Category**: Underspecified interfaces
- **Location**: ADR-025, acceptance criterion 3
- **What's missing**: `clientDataJSON = '{"challenge":"<base64(challenge)>","deviceId":"<base64(deviceId)>","type":"scp-device-attestation-v1"}'` with "(fields in this exact order, RFC 4648 base64, no line breaks)." JSON does not guarantee field ordering. If any layer (serialization library, transport, intermediate processing) re-orders the fields, the hash changes and attestation verification fails. The ADR does not specify how field ordering is enforced -- manual string construction? A canonical JSON library? serde_json with `preserve_order`?
- **Why it matters**: Silent attestation failures on a subset of devices due to JSON serialization ordering differences.
- **Severity**: HIGH

### [ADR-029] H9: CommitRangeRequest Uses Application Message at Stale Epoch
- **Category**: Missing security analysis
- **Location**: ADR-029, section 3, "Peer request"
- **What's missing**: "The reconnecting member broadcasts a `CommitRangeRequest` as an MLS application message (using their current epoch keys -- they can still encrypt at their stale epoch)." This assumes the stale epoch keys are still valid for encryption. But ADR-001 criterion 6 specifies a grace window after which old epoch keys are destroyed. If the member has been offline longer than the grace window, they cannot encrypt at their stale epoch. The ADR does not address this contradiction.
- **Why it matters**: For Tier 2 offline durations (4 hours to 7 days), the grace window may have expired, making CommitRangeRequest undeliverable through the normal channel. The peer request fallback fails silently.
- **Severity**: HIGH

### [ADR-029] H10: Event Log Reconciliation Trusts Peer-Provided Events
- **Category**: Missing security analysis
- **Location**: ADR-029, section 6, "Event Log Reconciliation"
- **What's missing**: "The reconnecting member requests the missing events via event range requests. Events are verified by recomputing the Merkle path from each event to the known root." But the events are provided by a peer. A malicious peer could provide fabricated events that form a valid Merkle tree but have false content. Verification against the Merkle root only proves structural integrity, not content authenticity. Individual event signatures are not mentioned as a verification step.
- **Why it matters**: A compromised peer could inject fabricated governance events (role changes, tool registrations) into a reconnecting member's event log.
- **Severity**: HIGH

### [ADR-031] H11: Governance Freeze on Simultaneous Commit is Exploitable
- **Category**: Missing security analysis
- **Location**: ADR-031, section 7, "Simultaneous commit"
- **What's missing**: If two conflicting proposals land at the same event log sequence, the context freezes governance until `ResolveConflict` passes. A malicious member with `GovernancePropose` capability could deliberately create conflicting proposals to freeze governance repeatedly. The `ResolveConflict` action itself requires governance quorum, meaning the freeze persists until quorum is reached. No rate limiting on proposals is specified.
- **Why it matters**: Governance denial-of-service by a single member with propose capability.
- **Severity**: HIGH

### [ADR-038] H12: WrappedCek member_id 8-byte Truncation -- Birthday Collision at Scale
- **Category**: Missing security analysis
- **Location**: ADR-038, section 4, `WrappedCek.member_id`
- **What's missing**: The ADR claims "collision probability for 8-byte hashes is ~1 in 10^18." This is the collision probability for a specific pair. For birthday-bound collisions across a group, at ~2^32 (~4 billion) distinct DIDs, the probability of any collision reaches ~50%. While this is far beyond typical context sizes, it creates a systemic risk: if ANY two DIDs in the protocol's entire lifetime collide on their 8-byte truncated hash, one member could silently decrypt another's content using the wrong access key. The failure mode is silent and undetectable.
- **Why it matters**: For a protocol designed to scale, 8 bytes provides only 64 bits of collision resistance. Industry standard for this type of identifier is 16 bytes minimum.
- **Severity**: HIGH

### [ADR-038] H13: AES-256-GCM AAD Binding Only Mentioned in MEMORY.md, Not in ADR
- **Category**: Scope gaps
- **Location**: ADR-038, section 4
- **What's missing**: The project MEMORY.md states "AES-GCM AAD binding: context_id || sender_did || sequence_number" but ADR-038 itself never specifies what the Additional Authenticated Data (AAD) is for the AES-256-GCM encryption of content. The `WrappedContent` struct shows `ciphertext` and `nonce` but no AAD field. Without AAD binding, wrapped content can be transplanted between contexts (cross-context replay).
- **Why it matters**: Lack of AAD binding in the wire format means ciphertext is not cryptographically bound to its context, sender, or position -- enabling cross-context content replay.
- **Severity**: HIGH

---

## Medium Findings

### [ADR-017] M1: ParticipationRecord Has No Signature or Integrity Protection
- **Category**: Missing security analysis
- **Location**: ADR-017, `ParticipationRecord` struct
- **What's missing**: `ParticipationRecord` is "computed locally from event logs" and includes an `event_log_root` Merkle root. But the struct itself has no signature. When shared between agents (for trust evaluation), there is no way to verify who computed it or whether it has been tampered with.
- **Why it matters**: Agents exchange trust inputs for evaluation. Without integrity protection, a malicious agent could present fabricated participation records.
- **Severity**: MEDIUM

### [ADR-017] M2: Attestation Revocation Check Has No Specified Protocol
- **Category**: Underspecified interfaces
- **Location**: ADR-017, acceptance criterion 3, `verify_attestation`
- **What's missing**: "Checks revocation: queries revocation status." How? Where is the revocation list? Is it per-context, per-DID, global? Is it a CRL, an OCSP-like protocol, or something else? The ProtocolRepository integration mentions "Store revocation list state per context" but no query protocol is defined.
- **Why it matters**: Without a revocation check protocol, attestation revocation is unenforceable.
- **Severity**: MEDIUM

### [ADR-017] M3: ConsequenceTrigger::Custom(String) Has No Validation
- **Category**: Missing security analysis
- **Location**: ADR-017, `ConsequenceTrigger::Custom(String)`
- **What's missing**: Custom triggers accept any string with no validation, no namespace, no authority boundary. This is the same problem ADR-041 solves for capabilities. Custom consequence triggers have no defined evaluation semantics.
- **Why it matters**: Arbitrary custom triggers could be used to create nonsensical or exploitable consequence rules.
- **Severity**: MEDIUM

### [ADR-018] M4: TTL Timer Behavior on Process Restart Unspecified
- **Category**: Scope gaps
- **Location**: ADR-018, acceptance criterion 2
- **What's missing**: "TTL timer spawned at context creation via tokio." Tokio timers do not survive process restarts. The ADR does not specify how TTL is enforced after an app restart -- is the remaining TTL persisted? Is it recomputed from context creation time? What happens if the device clock has drifted?
- **Why it matters**: Mobile apps are frequently killed and restarted. TTL enforcement that only works while the process is running provides no real guarantee.
- **Severity**: MEDIUM

### [ADR-018] M5: Key Destruction Attestation Not Linked to Specific Keys
- **Category**: Underspecified interfaces
- **Location**: ADR-018, acceptance criterion 7
- **What's missing**: `KeyDestructionLevel` records the assurance level but does not identify WHICH keys were destroyed. The attestation is per-close-event, not per-key. If some keys are destroyed at hardware level and others at software level, the single attestation level is ambiguous.
- **Why it matters**: Overly coarse attestation reduces the usefulness of the destruction verification metadata.
- **Severity**: MEDIUM

### [ADR-019] M6: DataProvenance.age Field Has No Clock Source Specification
- **Category**: Missing defaults
- **Location**: ADR-019, `DataProvenance.age: Duration`
- **What's missing**: `age` is a `Duration` but there is no specification of when it is computed (at attachment time? at evaluation time?) or what clock is used. Is this relative to the source context's creation time? The most recent modification? The time of the cross-context data flow?
- **Why it matters**: Ambiguous age semantics make provenance quality evaluation unreliable.
- **Severity**: MEDIUM

### [ADR-020] M7: Discovery Bootstrap Default Context IDs Not Specified
- **Category**: Missing defaults
- **Location**: ADR-020, acceptance criterion 8
- **What's missing**: "SDK ships configurable default bootstrap context IDs." But no actual default context IDs are listed. Who creates these contexts? How are they bootstrapped? What if they do not exist yet at launch?
- **Why it matters**: Discovery is useless without at least one default context. The bootstrapping problem is punted.
- **Severity**: MEDIUM

### [ADR-020] M8: Two-Tier Membership Write/Read Isolation Not Cryptographically Enforced
- **Category**: Missing security analysis
- **Location**: ADR-020, acceptance criteria 4-5
- **What's missing**: Writers are MLS members; readers are not. But the ADR does not specify how readers query the context without MLS membership. If readers send requests through the relay, they can observe MLS ciphertext. If they query through a tool endpoint, how is that endpoint authenticated and how does it access the MLS-encrypted registration data?
- **Why it matters**: The two-tier model's security properties depend on a reader-query mechanism that is not defined.
- **Severity**: MEDIUM

### [ADR-021] M9: DeviceAttestationProvider Callback Interface Missing Platform Identifier
- **Category**: Underspecified interfaces
- **Location**: ADR-021, `DeviceAttestationProvider` callback interface
- **What's missing**: The `attest` method returns raw bytes, but there is no field indicating which attestation platform produced the token (App Attest vs Play Integrity vs software-only). The relay verifying the attestation needs to know which verification endpoint to call. This information must be conveyed somehow.
- **Why it matters**: Without a platform identifier, the server-side verification path is ambiguous.
- **Severity**: MEDIUM

### [ADR-022] M10: getBridge() Race Condition on Concurrent First Call
- **Category**: Missing security analysis
- **Location**: ADR-022, `internal/bridge.ts`, `getBridge()` function
- **What's missing**: `getBridge()` checks `if (_bridge !== null) return _bridge` then does async initialization. If two async paths call `getBridge()` concurrently before the first call completes, both will enter the initialization branch. For WASM, `initWasm()` will be called twice. The ADR does not address this race condition.
- **Why it matters**: Double WASM initialization could cause memory corruption or undefined behavior depending on the wasm-bindgen implementation.
- **Severity**: MEDIUM

### [ADR-023] M11: Shadow Identity Platform Handle Verification Unspecified
- **Category**: Underspecified interfaces
- **Location**: ADR-023, `ClaimRequest` struct
- **What's missing**: "Protocol verifies attestation matches shadow's platform handle." How is the platform handle verified? For a Slack handle, who verifies the claimant actually owns that Slack account? The identity attestation (section 3.5) proves the claimant holds a DID, but does not prove they own the platform handle. The bridge operator could verify, but the trust model for bridge-mediated verification is not specified.
- **Why it matters**: Without platform handle verification, any DID can claim any shadow identity, stealing attribution for another user's actions.
- **Severity**: MEDIUM

### [ADR-023] M12: Bridge Provenance Does Not Track Multiple Bridge Hops
- **Category**: Scope gaps
- **Location**: ADR-023, `BridgeProvenance` struct
- **What's missing**: `BridgeProvenance` tracks one bridge connector ID and one originating platform. If content crosses from Platform A -> Bridge 1 -> SCP Context -> Bridge 2 -> Platform B, the intermediate SCP hop is lost. The provenance should compose with the chain_path mechanism from ADR-019.
- **Why it matters**: Multi-hop bridge scenarios lose accountability tracking.
- **Severity**: MEDIUM

### [ADR-024] M13: MLS Key Export Label and Context Not Specified
- **Category**: Missing defaults
- **Location**: ADR-024, acceptance criterion 2
- **What's missing**: `export_media_keys(mls_group, label, context, length) -> MediaKeyMaterial`. What are the values of `label`, `context`, and `length`? These are critical for domain separation of the MLS exporter. If different applications use the same label/context, they derive the same keys, breaking isolation.
- **Why it matters**: MLS exporter key derivation without specified label/context/length is a domain separation failure.
- **Severity**: MEDIUM

### [ADR-024] M14: Media Session Has No Authentication of SDP Content
- **Category**: Missing security analysis
- **Location**: ADR-024, `SignalingMessage` types
- **What's missing**: SDP offers/answers flow as SCP messages (encrypted, authenticated). But the `SessionDescription` struct contains a raw `sdp: String` field. SDP parsing is notoriously vulnerable to injection attacks. The ADR does not specify SDP validation or sanitization before passing to the WebRTC stack.
- **Why it matters**: Malicious SDP content delivered through the encrypted channel could exploit WebRTC implementation vulnerabilities.
- **Severity**: MEDIUM

### [ADR-025] M15: AppleKeyCustody Does Not Specify Key Backup Prevention
- **Category**: Scope gaps
- **Location**: ADR-025, acceptance criteria 1-2
- **What's missing**: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` prevents iCloud Keychain sync, which is correct. But the ADR does not address iTunes/Finder encrypted backups, which CAN include Keychain items with this protection class if the backup is encrypted. A device backup could export SCP private keys.
- **Why it matters**: Unintended key exfiltration through device backups.
- **Severity**: MEDIUM

### [ADR-027] M16: Software Key Fallback Stores Keys in ConcurrentHashMap -- Not Persistent
- **Category**: Decisions without implementation guidance
- **Location**: ADR-027, `AndroidKeyCustody.kt`, `softwareKeys` field
- **What's missing**: `private val softwareKeys = ConcurrentHashMap<String, AsymmetricCipherKeyPair>()` is an in-memory map. The ADR mentions "EncryptedSharedPreferences" for API 26-32 software keys but the code sample does not persist to EncryptedSharedPreferences. If the app is killed, software keys are lost.
- **Why it matters**: Key loss on process kill means identity loss on older Android devices.
- **Severity**: MEDIUM

### [ADR-029] M17: Outbound Queue Inner Envelopes Contain Stale Signatures
- **Category**: Missing security analysis
- **Location**: ADR-029, section 1
- **What's missing**: "Messages are serialized to their inner envelope form (signed, padded) but NOT MLS-encrypted." The inner envelope signature binds to the sender's current signing key at queue time. If the sender rotates their signing key while offline (or between queue and drain), the queued inner envelopes have signatures from the old key. Recipients may reject these as invalid if the old key has been rotated out of the DID document.
- **Why it matters**: Key rotation between queue and drain silently invalidates all queued messages.
- **Severity**: MEDIUM

### [ADR-029] M18: Multi-Device Queue Deduplication Relies on Payload Hash -- Allows Targeted Suppression
- **Category**: Missing security analysis
- **Location**: ADR-029, section 7
- **What's missing**: "If multiple devices queued the same message, the first device to drain delivers; the second recognizes the duplicate payload_hash." A malicious relay that knows the payload_hash (it is in the inner envelope which the relay cannot read -- but if the relay compromises one device, it learns the hash) could inject a message with the same payload_hash before the legitimate drain, causing the legitimate message to be discarded as a duplicate.
- **Why it matters**: Targeted message suppression through payload hash collision.
- **Severity**: MEDIUM

### [ADR-030] M19: Checkpoint State Snapshot Is Extremely Large at Scale
- **Category**: Scope gaps
- **Location**: ADR-030, `ContextStateSnapshot` struct
- **What's missing**: `ContextStateSnapshot` includes `membership: Vec<(DID, RoleName)>`, `tools: Vec<ToolRegistration>`, `sender_key_epochs: Vec<(DID, u64)>`, `blocks: Vec<(DID, DID)>`, and `ucan_revocations: Vec<String>`. For a context with 500 members and 100 tools, the snapshot could be hundreds of kilobytes. The ADR does not specify a maximum snapshot size or compression strategy, and this is published as an event log entry.
- **Why it matters**: Large checkpoint events dominate storage on mobile devices and increase relay bandwidth costs.
- **Severity**: MEDIUM

### [ADR-030] M20: 30-Day Minimum Retention Interacts Poorly with Ephemeral Contexts
- **Category**: Contradictions with other ADRs
- **Location**: ADR-030, section 2
- **What's missing**: ADR-018 defines Ephemeral memory scope as "destroys keys immediately" on context close. ADR-030 defines a 30-day minimum retention for event logs. For an ephemeral context that closes after 1 hour, the event log must be retained for 30 days even though the content keys are destroyed. This creates a metadata retention obligation that conflicts with the ephemeral intent.
- **Why it matters**: Ephemeral contexts that retain event log metadata for 30 days leak participation history (who was present, when, what tool invocations occurred) long after the content is unreadable.
- **Severity**: MEDIUM

### [ADR-031] M21: GovernanceAction Variants Missing Size Limits
- **Category**: Missing defaults
- **Location**: ADR-031, section 3, `GovernanceAction` enum
- **What's missing**: `GovernanceAction::RegisterTool { registration: ToolRegistration }` and `GovernanceAction::CreateChildContext { params: Box<ContextParams> }` embed potentially large payloads. No size limits are specified for these embedded objects. A malicious proposer could create proposals with arbitrarily large tool registrations or context params.
- **Why it matters**: Resource exhaustion through oversized governance proposals stored in the event log.
- **Severity**: MEDIUM

### [ADR-041] M22: Protocol Registry "Signed" But Signing Mechanism Not Specified
- **Category**: Decisions without implementation guidance
- **Location**: ADR-041, consequences
- **What's missing**: "The protocol registry is versioned and signed." Signed by whom? With what key? How is the signing key distributed? How are registry updates authenticated? Is it embedded in the SDK binary? Is it a separate downloadable artifact? None of this is specified.
- **Why it matters**: Without a concrete signing and distribution mechanism, the "signed protocol registry" is an unimplemented concept.
- **Severity**: MEDIUM

---

## Low Findings

### [ADR-017] L1: `serde_json::Value` for Attestation Claim and Challenge Parameters
- **Category**: Underspecified interfaces
- **Location**: ADR-017, `Attestation.claim` and `ChallengeRequest.parameters`
- **What's missing**: Both use `serde_json::Value` as a catch-all. No schema is defined for what constitutes a valid claim or valid challenge parameters per attestation/challenge type.
- **Why it matters**: Untyped JSON is a deserialization attack surface and prevents static validation.
- **Severity**: LOW

### [ADR-018] L2: RelayDeletionRequest Has No Authentication
- **Category**: Underspecified interfaces
- **Location**: ADR-018, `RelayDeletionRequest` struct
- **What's missing**: The struct contains `relay_url`, `blob_ids`, `context_id`, `requested_at` but no signature or authentication token. How does the relay verify the deletion request is authorized?
- **Why it matters**: Unauthenticated deletion requests could be used to delete other contexts' data from relays.
- **Severity**: LOW

### [ADR-020] L3: DiscoveryResultEntry.relevance_score Uses f64
- **Category**: Contradictions with other ADRs
- **Location**: ADR-020, `DiscoveryResultEntry.relevance_score: f64`
- **What's missing**: Same `f64` issue as M4/C4 but lower severity because relevance scores are not used in security-critical comparisons. Still prevents `Eq` derivation if the struct needs it.
- **Why it matters**: Consistency concern, not a security issue.
- **Severity**: LOW

### [ADR-022] L4: TypeScript receive() Generator Does Not Handle Backpressure
- **Category**: Scope gaps
- **Location**: ADR-022, `Context.receive()` implementation
- **What's missing**: The `receive()` method uses an unbounded `queue: Message[]` array. If the consumer is slower than the producer, the queue grows without bound. No maximum queue size or drop policy is specified.
- **Why it matters**: Memory exhaustion in the browser for high-throughput contexts.
- **Severity**: LOW

### [ADR-024] L5: MediaSession Has No Maximum Participant Limit
- **Category**: Missing defaults
- **Location**: ADR-024, `MediaSession` struct
- **What's missing**: `participants: Vec<DID>` has no specified maximum. WebRTC scales poorly beyond ~50 participants for audio and ~10 for video. No guidance is provided.
- **Why it matters**: Quality of experience degradation, not a security issue.
- **Severity**: LOW

### [ADR-025] L6: AppleStorage File Protection Set After File Creation
- **Category**: Scope gaps
- **Location**: ADR-025, code example
- **What's missing**: `FileManager.default.setAttributes([.protectionKey: ...])` is called on an existing file path. If the SQLCipher database is created before the protection attribute is set, there is a brief window where the file exists without protection.
- **Why it matters**: Very narrow race condition, but the protection should be set on the directory before the file is created.
- **Severity**: LOW

### [ADR-026] L7: SCPContext deinit Schedules Unstructured Task
- **Category**: Scope gaps
- **Location**: ADR-026, `SCPContext.deinit`
- **What's missing**: `deinit { let h = handle; Task { try? await context_close(handle: h) } }` creates an unstructured Task. If the app is terminating, this task may never execute. The ADR acknowledges this is a "safety net" but does not discuss the termination case.
- **Why it matters**: Resource cleanup is not guaranteed on app termination. Low severity because this is a known limitation of `deinit` in Swift.
- **Severity**: LOW

### [ADR-028] L8: Kotlin Context.close() Launches Coroutine Then Immediately Cancels Scope
- **Category**: Scope gaps
- **Location**: ADR-028, `Context.close()` implementation
- **What's missing**: `scope.launch { runCatching { leave() } }` followed by `scope.cancel()`. The `cancel()` may cancel the `leave()` coroutine before it completes, defeating the purpose. The `launch` runs on the scope being cancelled.
- **Why it matters**: `close()` may not actually leave the context gracefully.
- **Severity**: LOW

### [ADR-029] L9: OfflineTier Boundary Values Are Arbitrary Without Justification
- **Category**: Missing defaults
- **Location**: ADR-029, section 6, `classify_offline_duration`
- **What's missing**: 4 hours and 7 days are the tier boundaries. The rationale section says "95%+ of offline events" are Tier 1 but provides no data source for this claim. Are these boundaries configurable per context?
- **Why it matters**: Fixed boundaries may not suit all deployment scenarios. Not a security issue, but an operability concern.
- **Severity**: LOW

### [ADR-031] L10: ProposalId Computed from SHA-256 But Not Verified as Unique
- **Category**: Scope gaps
- **Location**: ADR-031, `ProposalId` type
- **What's missing**: `ProposalId = SHA-256(context_id || proposer_did || action_hash || timestamp)`. If two identical proposals are submitted at the same timestamp (within the same second), they produce the same ProposalId. No uniqueness check is specified.
- **Why it matters**: Proposal ID collision could cause one proposal to overwrite another in storage.
- **Severity**: LOW

### [ADR-041] L11: 27 Capability URIs Listed But No Test Vector Suite
- **Category**: Underspecified interfaces
- **Location**: ADR-041, acceptance criteria
- **What's missing**: The URI parser is specified but no test vectors are provided for parsing edge cases (unicode, percent-encoding, version number boundaries, DID-scoped capabilities with unusual DID methods).
- **Why it matters**: Parser divergence across SDK implementations.
- **Severity**: LOW

---

## Structural Concerns

### SC1: ADR-030/ADR-031 Retention Multiplier Type Inconsistency Pattern
ADR-031 correctly identifies that `f64` prevents `Eq` derivation and uses `u32` basis points for `min_participation_bps`. But ADR-030 uses `f64` for `structural_retention_multiplier` and `operational_retention_multiplier`. The implementation (`scp-event-log/src/pruning.rs`) also uses `f64`. AND the governance implementation (`scp-core/src/context/governance/majority.rs`) uses `f64` for `min_participation`, contradicting what ADR-031 specifies. This is a systemic type-consistency issue that needs a project-wide decision: either all comparison-sensitive numeric types use basis points, or a canonical `f64` comparison strategy is defined for serialization and equality.

### SC2: ADR-034 Creates a Maintenance Burden That Will Grow Unboundedly
The WASM re-implementation strategy means every new feature added to scp-core must be independently re-implemented in the WASM bridge. This is acknowledged as "the same category of risk that any multi-implementation protocol faces" -- but SCP is not a multi-implementation protocol. It is a single-implementation protocol that chose to have two implementations for deployment convenience. The maintenance and security testing burden of this decision will compound with every release.

### SC3: Trust Engine (ADR-017) Is the Thinnest Security-Critical ADR
ADR-017 defines the trust evaluation inputs for the entire protocol. It specifies types and function signatures but leaves the core algorithms unspecified: independence scoring, attestation quality evaluation formulas, consequence rule evaluation semantics for custom triggers, and the interaction between participation records and trust evaluation. This is the ADR most in need of a follow-up specification pass.

### SC4: Access Key Layer (ADR-038) Compliance Model Is Trust-Based, Not Cryptographic
The entire Layer 3 security guarantee depends on SDK compliance -- "all compliant SDKs delete the target's access key." This is a trust-based model, not a cryptographic one. The ADR correctly identifies the three enforcement layers, but Layer 3's effectiveness degrades to zero against a single non-compliant client. For a protocol that claims cryptographic enforcement of content access, this is a significant gap in the threat model's honesty.

---

## What Is Actually Good

1. **ADR-031 (Multi-Admin Governance)** is excellent. The governance engine trait is clean, the four models are well-specified with concrete resolution rules, the conflict detection and deadlock recovery mechanisms are thoughtful, and the integration with MLS epochs and UCAN delegation is carefully analyzed. The basis-point choice for participation threshold shows awareness of the `f64`/`Eq` problem even though other ADRs do not follow suit.

2. **ADR-029 (Offline/Sync)** tackles the hardest problem in the protocol honestly. The three-tier classification is well-justified, the six-phase reconnection protocol is concrete and ordered, and the decision to defer MLS encryption until drain time is cryptographically sound.

3. **ADR-038 (Content Access Key Layer)** makes a correct architectural decision with the three-layer enforcement model. The explicit omission of `content_hash` (to avoid a confirmation oracle) shows genuine cryptographic thinking. The forward-only restoration semantics are the right call.

4. **ADR-025/027 (Platform Adapters)** are refreshingly honest about hardware limitations. The Secure Enclave P-256 constraint is stated plainly rather than hidden. The TEE-over-StrongBox decision for Android is well-justified with performance data.

5. **Cross-ADR consistency** is generally strong. Dependencies are explicitly mapped, acceptance criteria reference specific other ADRs, and the FFI bridge pattern (flat surface, opaque/value type split, callback interfaces) is consistent across all four SDK ADRs.

---

## Summary Statistics

| Severity | Count |
|----------|-------|
| CRITICAL | 6 |
| HIGH | 14 |
| MEDIUM | 22 |
| LOW | 11 |
| **Total** | **53** |

| Category | Count |
|----------|-------|
| Missing security analysis | 16 |
| Underspecified interfaces | 8 |
| Missing defaults | 7 |
| Scope gaps | 10 |
| Decisions without implementation guidance | 4 |
| Contradictions with other ADRs | 4 |
| Incomplete decisions | 4 |
