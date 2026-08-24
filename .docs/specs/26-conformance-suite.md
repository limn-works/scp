# 26. Conformance Test Suite

## 26.1 Purpose

This section defines the conformance test suite for independent SCP implementations. A conformance test is a protocol-level test that verifies an implementation handles multi-step interactions correctly — distinct from unit tests (implementation details) and test vectors (individual cryptographic constructions, §25).

Conformance is split into two tiers:

- **SCP Core Conformance** — identity, contexts, messaging, and sync. The minimum bar for interoperability.
- **SCP Full Conformance** — all protocol layers including trust, discovery, economy, and bridges.

All tests target SCP protocol version 1.

## 26.2 Test Format

Each test specifies:

| Field | Description |
|-------|-------------|
| **ID** | `CONF-NNN` — unique, stable identifier. |
| **Layer** | Protocol layer (Identity, Context, Messaging, Sync, Trust, Transport, Discovery, Economy, Bridge). |
| **Tier** | Core or Full. |
| **Spec Sections** | Which spec sections the test covers. |
| **Preconditions** | Required state before the test begins. |
| **Steps** | Numbered, deterministic procedure. |
| **Expected Outcome** | Observable, machine-verifiable result. |

## 26.3 Identity Tests (§3, §4)

### CONF-001: DID Creation with Required Verification Methods

| Field | Value |
|-------|-------|
| **Layer** | Identity |
| **Tier** | Core |
| **Spec Sections** | §3.1, §3.2, ADR-039 |
| **Preconditions** | None. |
| **Steps** | 1. Generate Ed25519 keypair. 2. Create did:dht DID. 3. Build DID document with verification methods `#0` (root), `#active` (signing), `#agent` (agent signing). |
| **Expected Outcome** | The **relay-layer** DID document (§18.2.2A) contains exactly 3 verification methods with IDs `#0`, `#active`, `#agent`. All are Ed25519VerificationKey2020. The DID string is the z-base-32 encoding of the `#0` public key. The Mainline bootstrap core carries `#active` alone and derives `#0` from the DID string (§18.2.2C), so this count is not asserted against a Mainline resolution. |

### CONF-002: DID Resolution and Self-Certification

| Field | Value |
|-------|-------|
| **Layer** | Identity |
| **Tier** | Core |
| **Spec Sections** | §3.1, §9.6.1 |
| **Preconditions** | Bootstrap core (§18.2.2C) published to Mainline DHT (or test DHT) as a did:dht-conformant DNS packet. |
| **Steps** | 1. Resolve DID via DHT lookup. 2. Verify BEP44 signature against the public key encoded in the DID string. 3. Decode the DNS packet into the bootstrap core. |
| **Expected Outcome** | BEP44 signature verification succeeds. The decoded bootstrap core matches the core that was published to Mainline, byte for byte. The public key embedded in the DID string matches `#0`, which the core carries by derivation rather than as an entry. The resolution returns the `BootstrapCore` variant of `ResolvedDidDocument` (§3.10.10), whose payload type carries no relay-layer entry, and the implementation MUST NOT compare these bytes against the relay layer's JSON document — the two layers carry different encodings (§18.2.2A). |

### CONF-003: Key Rotation (Active Key Update)

| Field | Value |
|-------|-------|
| **Layer** | Identity |
| **Tier** | Core |
| **Spec Sections** | §3.3, §3.9, §9.7.1, §9.11 |
| **Preconditions** | DID with established `#active` key. Existing messages signed with old key. |
| **Steps** | 1. Generate new Ed25519 keypair for `#active`. 2. Update DID document with new `#active` key. 3. Publish to both layers, each in its own encoding, incrementing each layer's own sequence number (§3.10.5). 4. Resolve the DID from the relay layer again. 5. Verify the old `#active` key is no longer referenced by `authentication` or `assertionMethod`. 6. Verify key continuity fingerprint changed. 7. Resolve the DID from Mainline and assert its bootstrap core carries the NEW `#active` key — a publisher that rotated on one layer only fails here, and the relay-layer assertion in step 5 cannot catch it. |
| **Expected Outcome** | New DID document has the new `#active` key, and neither `authentication` nor `assertionMethod` references the old one. Key continuity fingerprint (§9.11) reflects the change. **Three further assertions, restored and extended by Alec's decision of 2026-08-17 (`.docs/specs/00-open-questions.md`, "Retired verification methods"):** the old `#active` key is **present** in `verificationMethod` as `#retired-{sequence}`, which ADR-003 §4a requires `rotate_active_key` to retain (`.docs/adrs/phase-1.md`); a content signature made with the old key **verifies against that retired method** after rotation (§3.9 of `.docs/specs/03-identity.md`); and a KeyPackage attestation signed by that same retired method is **rejected** (§9.7.1 of `.docs/specs/09-security-model.md` check 1), which is the boundary between a statement about the past and a bearer capability. This test previously asserted the old key was absent; that assertion contradicted ADR-003 §4a, a later revision suspended both, and the decision restores them in the form stated here. |

### CONF-004: Agent Binding (Human DID Attests Agent DID)

| Field | Value |
|-------|-------|
| **Layer** | Identity |
| **Tier** | Core |
| **Spec Sections** | §4.2, ADR-039 |
| **Preconditions** | Human DID and agent DID both created. |
| **Steps** | 1. Create identity attestation binding agent DID to human DID. 2. Sign attestation with human's `#active` key. 3. Verify attestation signature. 4. Verify agent DID's `#agent` key matches the key in the attestation. |
| **Expected Outcome** | Attestation is valid. Agent DID traces to human DID through the attestation chain. |

### CONF-005: Multi-Device (Same DID, Different Device Keys)

| Field | Value |
|-------|-------|
| **Layer** | Identity |
| **Tier** | Core |
| **Spec Sections** | §3.4 |
| **Preconditions** | DID exists on device A. |
| **Steps** | 1. On device B, derive device-specific signing material from the same DID. 2. Both devices sign messages. 3. Both signatures verify against the DID document. |
| **Expected Outcome** | Both devices can sign messages that verify against the same DID. The DID document is the single source of truth. |

## 26.4 Context Tests (§5, §6)

### CONF-006: Create Context with MLS Group

| Field | Value |
|-------|-------|
| **Layer** | Context |
| **Tier** | Core |
| **Spec Sections** | §5.1, §9.7 |
| **Preconditions** | Creator has a DID. Relay is available. |
| **Steps** | 1. Create context with parameters (name, mode: encrypted, ceiling, governance model). 2. Initialize MLS group with creator as sole member. 3. Publish context metadata to relay. |
| **Expected Outcome** | Context ID is derived from initial parameters. MLS group is established. Context metadata is retrievable from relay. Creator holds the only MLS leaf node. |

### CONF-007: Join Context via Invitation

| Field | Value |
|-------|-------|
| **Layer** | Context |
| **Tier** | Core |
| **Spec Sections** | §5.3, §9.7 |
| **Preconditions** | Context exists with at least one member. Invitee has a DID. |
| **Steps** | 1. Existing member generates invitation (MLS KeyPackage fetch + Add proposal). 2. Invitee receives Welcome message. 3. Invitee processes Welcome and joins MLS group. 4. Invitee can decrypt messages sent after joining. |
| **Expected Outcome** | Invitee is a member of the MLS group. Invitee can decrypt new messages. Invitee cannot decrypt messages sent before joining (forward secrecy). |

### CONF-008: Leave Context

| Field | Value |
|-------|-------|
| **Layer** | Context |
| **Tier** | Core |
| **Spec Sections** | §5.5, §9.7 |
| **Preconditions** | Member is in an MLS group with 2+ members. |
| **Steps** | 1. Member sends Remove proposal for self. 2. Remaining members process the commit. 3. Verify removed member's leaf node is blank. 4. Send a message in the context. |
| **Expected Outcome** | Removed member is no longer in the MLS group. New messages cannot be decrypted by the removed member. MLS epoch advances. |

### CONF-009: Governance — Propose Role Change and Vote

| Field | Value |
|-------|-------|
| **Layer** | Context |
| **Tier** | Core |
| **Spec Sections** | §6.4 |
| **Preconditions** | Context with 3 members. Governance model: majority vote. |
| **Steps** | 1. Member A proposes role change for Member C. 2. Proposal ID is computed per §9.5.2 (domain: `"SCP-PROPOSAL-V1:"`). 3. Member A votes approve (signed per `"SCP-VOTE-V1:"`). 4. Member B votes approve. 5. Quorum reached (2/3). 6. Role change is applied. |
| **Expected Outcome** | Proposal passes with 2/3 votes. Member C's role is updated. Governance event recorded in event log. All vote signatures are verifiable. |

### CONF-010: Governance — Threshold Voting (k-of-n)

| Field | Value |
|-------|-------|
| **Layer** | Context |
| **Tier** | Core |
| **Spec Sections** | §6.4 |
| **Preconditions** | Context with 5 members. Governance model: 3-of-5 threshold. |
| **Steps** | 1. Propose parameter change. 2. Two members vote approve (below threshold). 3. Third member votes approve (meets threshold). 4. Verify proposal passes. 5. Verify a fourth vote does not double-apply. |
| **Expected Outcome** | Proposal passes exactly when the 3rd approval is received. Parameter change is applied once. |

### CONF-011: Context Parameter Update Through Governance

| Field | Value |
|-------|-------|
| **Layer** | Context |
| **Tier** | Core |
| **Spec Sections** | §5.6, §6.4 |
| **Preconditions** | Context with mutable parameters. |
| **Steps** | 1. Propose changing a context parameter (e.g., name). 2. Vote and pass the proposal. 3. Verify context metadata reflects the change. 4. Verify the change is recorded in the event log. |
| **Expected Outcome** | Context metadata is updated. Event log contains the parameter change event. All members see the updated metadata. |

### CONF-012: Nested Context Creation

| Field | Value |
|-------|-------|
| **Layer** | Context |
| **Tier** | Full |
| **Spec Sections** | §5.13 |
| **Preconditions** | Parent context exists. Creator is a member of parent. |
| **Steps** | 1. Create child context with parent reference. 2. If `ContextParams::max_nesting_depth` is set, verify nesting depth does not exceed it (§5.13.8, ADR-043). 3. Verify child ceiling is intersection of parent ceiling and requested ceiling (§5.13.1). 4. Verify child references parent in metadata. |
| **Expected Outcome** | Child context created. Ceiling intersection enforced. Parent-child relationship visible in metadata. |

### CONF-013: Context Close Lifecycle

| Field | Value |
|-------|-------|
| **Layer** | Context |
| **Tier** | Full |
| **Spec Sections** | §5.6 |
| **Preconditions** | Context with members and message history. |
| **Steps** | 1. Initiate context close (governance or TTL expiry). 2. Verify close event in event log. 3. Verify verification window (§9.18.6 — 300s default). 4. After window: verify no new messages accepted. 5. Verify key destruction per §9.15. |
| **Expected Outcome** | Context transitions to closed state. Messages rejected after close. Key material destroyed. |

## 26.5 Messaging Tests (§9)

### CONF-014: Send Message — Sign, Encrypt, Wrap

| Field | Value |
|-------|-------|
| **Layer** | Messaging |
| **Tier** | Core |
| **Spec Sections** | §9.5.2, §9.8, §9.10 |
| **Preconditions** | Sender is member of encrypted context. |
| **Steps** | 1. Construct InnerEnvelope with payload, provenance. 2. Sign with canonical hash (domain: `"SCP-INNER-ENVELOPE-V1:"`). 3. Encrypt with sender key (§9.16). 4. Pad to bucket boundary (§9.10). 5. Wrap in OuterEnvelope with routing pseudonym. 6. Send to relay. |
| **Expected Outcome** | Outer envelope is a valid bucket size. Inner envelope signature is verifiable by recipients. Relay sees only routing pseudonym and blob size. |

### CONF-015: Receive Message — Unwrap, Decrypt, Verify

| Field | Value |
|-------|-------|
| **Layer** | Messaging |
| **Tier** | Core |
| **Spec Sections** | §9.5.2, §9.8, §9.10 |
| **Preconditions** | Recipient is member of context. Has sender's sender key. |
| **Steps** | 1. Receive OuterEnvelope from relay. 2. Strip padding, recover original ciphertext. 3. Decrypt with sender key. 4. Verify InnerEnvelope signature against sender's DID document. 5. Verify epoch, sequence, timestamp. |
| **Expected Outcome** | Decryption succeeds. Signature verification succeeds. Plaintext matches original. |

### CONF-016: Padding Roundtrip

| Field | Value |
|-------|-------|
| **Layer** | Messaging |
| **Tier** | Core |
| **Spec Sections** | §9.10 |
| **Preconditions** | None. |
| **Steps** | 1. For each payload size in [0, 1, 252, 253, 1020, 1021, 262140]: pad to bucket, then strip padding. 2. Verify recovered payload equals original. 3. Verify padded size is a valid bucket size. |
| **Expected Outcome** | All roundtrips succeed. Padded sizes are in `[256, 1024, 4096, 16384, 65536, 262144]`. |

### CONF-017: Sender Key Distribution — Establish, Rotate, Use

| Field | Value |
|-------|-------|
| **Layer** | Messaging |
| **Tier** | Core |
| **Spec Sections** | §9.16 |
| **Preconditions** | Two members in a context. |
| **Steps** | 1. Member A distributes sender key to Member B via HPKE (info: `"scp-sender-key-v1"`). 2. Member B decrypts and stores sender key. 3. Member A sends a message encrypted with the sender key. 4. Member B decrypts with stored sender key. 5. Member A rotates sender key (new epoch). 6. Member A sends SenderKeyEpochAdvance (signed). 7. Member B processes advance and updates key. 8. Messages with old key still decrypt during grace period (30s, §9.18.8). |
| **Expected Outcome** | Key distribution succeeds. Messages encrypt/decrypt correctly. Key rotation works. Grace period honored. |

### CONF-018: Access Key Layer — CEK Distribution

| Field | Value |
|-------|-------|
| **Layer** | Messaging |
| **Tier** | Core |
| **Spec Sections** | §9.17 |
| **Preconditions** | Context with 3 members. All have access keys. |
| **Steps** | 1. Sender generates 32-byte CEK. 2. Wrap CEK with AES-256-KW for each member's access key. 3. Include wrapped CEKs in message. 4. Each recipient unwraps CEK with their access key. 5. All recipients decrypt the same message. |
| **Expected Outcome** | All 3 members recover the same CEK. Message decrypts identically for all. |

## 26.6 Sync Tests (§23)

### CONF-019: Minutes Offline — Sequential Commit Replay

| Field | Value |
|-------|-------|
| **Layer** | Sync |
| **Tier** | Core |
| **Spec Sections** | §23 |
| **Preconditions** | Member was offline for < 4 hours. Context had activity during absence (< 100 epochs). |
| **Steps** | 1. Member reconnects. 2. Exchanges consistency checkpoints with peers. 3. Identifies missing epochs. 4. Replays commits sequentially. 5. Verifies MLS state converges with online members. |
| **Expected Outcome** | Member's MLS epoch matches current epoch. All missed messages are recoverable. No state divergence. |

### CONF-020: Days Offline — Snapshot + Delta

| Field | Value |
|-------|-------|
| **Layer** | Sync |
| **Tier** | Core |
| **Spec Sections** | §23 |
| **Preconditions** | Member was offline for 4h–7d. > 100 epochs have passed. |
| **Steps** | 1. Member reconnects. 2. Requests snapshot from peers. 3. Applies snapshot. 4. Applies delta (commits since snapshot). 5. Verifies MLS state converges. |
| **Expected Outcome** | Member syncs to current epoch. Snapshot application is correct. Delta replay brings member to current state. |

### CONF-021: Weeks Offline — Full Reset

| Field | Value |
|-------|-------|
| **Layer** | Sync |
| **Tier** | Core |
| **Spec Sections** | §23.5 |
| **Preconditions** | Member was offline for > 7 days. Epoch drift > 1000. |
| **Steps** | 1. Member sends ResetRequest (signed per `"SCP-RESET-REQUEST-V1:"`). 2. Admin processes reset request. 3. Admin sends MLS Welcome. 4. Member processes Welcome within 60s timeout (§9.18.9). 5. Member joins as fresh member. |
| **Expected Outcome** | Member is re-admitted to the MLS group. Fresh epoch state. Historical messages not accessible (re-join, not restore). |

### CONF-022: Equivocation Detection

| Field | Value |
|-------|-------|
| **Layer** | Sync |
| **Tier** | Full |
| **Spec Sections** | §9.9 |
| **Preconditions** | Context with event log. |
| **Steps** | 1. Member publishes two conflicting events with same sequence number. 2. Other members detect conflicting Merkle proofs. 3. Equivocation event is recorded. |
| **Expected Outcome** | Conflicting events detected. Equivocation is attributable to the offending member. Protocol flags the inconsistency. |

## 26.7 Trust Tests (§7)

### CONF-023: UCAN Issuance and Verification

| Field | Value |
|-------|-------|
| **Layer** | Trust |
| **Tier** | Core |
| **Spec Sections** | §7, §9.5 |
| **Preconditions** | Issuer has Ed25519 keypair. |
| **Steps** | 1. Construct UCAN token with: issuer, audience, capabilities, nonce, expiry. 2. Sign with Ed25519. 3. Verify signature. 4. Verify nonce freshness (within 5 min tolerance, §9.18.7). 5. Verify expiry < 24h (§9.18.7). |
| **Expected Outcome** | Token verifies. Nonce and expiry constraints pass. |

### CONF-024: UCAN Delegation Chain (A -> B -> C)

| Field | Value |
|-------|-------|
| **Layer** | Trust |
| **Tier** | Full |
| **Spec Sections** | §7 |
| **Preconditions** | Three DIDs: A (root), B (delegate), C (sub-delegate). |
| **Steps** | 1. A issues UCAN to B with capability X. 2. B issues UCAN to C with capability X (or subset). 3. C presents token. 4. Verifier validates full chain: C's token → B's token → A's authority. |
| **Expected Outcome** | Chain validates. Each link's signature verifies. Capability attenuation is correct. |

### CONF-025: UCAN Revocation

| Field | Value |
|-------|-------|
| **Layer** | Trust |
| **Tier** | Full |
| **Spec Sections** | §7, §9.5 |
| **Preconditions** | Valid UCAN token exists. |
| **Steps** | 1. Compute token CID (CIDv1, SHA-256, DAG-CBOR). 2. Add CID to context RevocationList. 3. Distribute revocation via MLS. 4. Attempt to exercise the revoked token. |
| **Expected Outcome** | Token exercise is denied. Revocation is recorded. CID computation matches between implementations. |

### CONF-026: Capability Attenuation (Subset Delegation)

| Field | Value |
|-------|-------|
| **Layer** | Trust |
| **Tier** | Full |
| **Spec Sections** | §7 |
| **Preconditions** | DID A has capabilities [read, write, admin]. |
| **Steps** | 1. A delegates [read, write] to B (subset). 2. B attempts to delegate [read, write, admin] to C (superset — should fail). 3. B delegates [read] to C (further attenuation — should succeed). |
| **Expected Outcome** | Step 2 fails — cannot delegate capabilities not held. Step 3 succeeds — attenuation is valid. |

## 26.8 Transport Tests (§10)

### CONF-027: Relay Connection — Subscribe, Publish, Receive

| Field | Value |
|-------|-------|
| **Layer** | Transport |
| **Tier** | Core |
| **Spec Sections** | §10.5 |
| **Preconditions** | Relay is running. Client has context subscription. |
| **Steps** | 1. Client subscribes to context on relay. 2. Another client publishes a message to the same context. 3. First client receives the message. |
| **Expected Outcome** | Message delivered within reasonable latency. Message content matches what was published. |

### CONF-028: Relay Store-and-Forward

| Field | Value |
|-------|-------|
| **Layer** | Transport |
| **Tier** | Core |
| **Spec Sections** | §10.5 |
| **Preconditions** | Client subscribed to context. Client goes offline. |
| **Steps** | 1. Client disconnects. 2. Messages are sent to the context while client is offline. 3. Client reconnects. 4. Client queries relay for missed messages. |
| **Expected Outcome** | All messages sent during offline period are retrievable. Messages arrive in order. Blob TTL is respected (§9.18.11). |

### CONF-029: Multi-Relay — Same Context Across Relays

| Field | Value |
|-------|-------|
| **Layer** | Transport |
| **Tier** | Full |
| **Spec Sections** | §10.5 |
| **Preconditions** | Context configured with 2 relay URLs. |
| **Steps** | 1. Member A connected to relay 1. 2. Member B connected to relay 2. 3. Member A sends message. 4. Verify Member B receives message (via relay federation or client-side multi-relay). |
| **Expected Outcome** | Messages are deliverable across relay boundaries. No message loss. |

## 26.9 Discovery Tests (§22)

### CONF-030: Handle Registration and Lookup

| Field | Value |
|-------|-------|
| **Layer** | Discovery |
| **Tier** | Full |
| **Spec Sections** | §22.3.1, §22.11 |
| **Preconditions** | Context exists with handle support. |
| **Steps** | 1. Register handle `alice` pointing to DID via `handle_register`. 2. Look up `alice` via `handle_lookup`. 3. Verify result contains the correct DID and metadata. 4. Attempt to register `alice` again from different DID — expect conflict. |
| **Expected Outcome** | Registration succeeds. Lookup returns correct DID. Duplicate registration returns `conflict`. |

### CONF-031: Agent Capability Registration and Search

| Field | Value |
|-------|-------|
| **Layer** | Discovery |
| **Tier** | Full |
| **Spec Sections** | §6.2.2B, §22.11 |
| **Preconditions** | Context exists. |
| **Steps** | 1. Register agent with capabilities `["scp:capability:translate/v1"]` via `agent_register`. 2. Search with `capability_filter: ["scp:capability:translate/v1"]` via `agent_search`. 3. Verify result includes the registered agent. 4. Deregister via `agent_deregister`. 5. Search again — agent absent. |
| **Expected Outcome** | Registration and search work. Deregistration removes agent from search results. |

### CONF-032: Push Notification Registration

| Field | Value |
|-------|-------|
| **Layer** | Discovery |
| **Tier** | Full |
| **Spec Sections** | §10.7.1, §22.11.4 |
| **Preconditions** | Relay supports push notifications. |
| **Steps** | 1. Register push subscription with platform, token, and context list. 2. Verify signature over registration fields. 3. Deregister. 4. Verify deregistration signature. |
| **Expected Outcome** | Registration accepted. Signatures verify. Deregistration succeeds. |

## 26.10 Economy Tests (§19)

### CONF-033: Cost Schedule Evaluation

| Field | Value |
|-------|-------|
| **Layer** | Economy |
| **Tier** | Full |
| **Spec Sections** | §19.3, §19.15 |
| **Preconditions** | Context with `EconomicPolicy` including cost schedule. |
| **Steps** | 1. Evaluate cost for `MessageSend` action. 2. Verify cost matches `per_message` in cost schedule. 3. Evaluate cost for `ContextJoin`. 4. Verify cost matches `per_join`. |
| **Expected Outcome** | Costs are deterministic and match the policy. |

### CONF-034: Payment Authorization -> Capture -> Receipt

| Field | Value |
|-------|-------|
| **Layer** | Economy |
| **Tier** | Full |
| **Spec Sections** | §19.6, §19.15.5 |
| **Preconditions** | Payment adapter available. Payer has spending UCAN. |
| **Steps** | 1. Create `PaymentAuthorization`. 2. Adapter captures payment. 3. Adapter returns `PaymentReceipt`. 4. Verify receipt signature. 5. Record receipt in event log. |
| **Expected Outcome** | Receipt signature verifies. Receipt is in event log. Payment is traceable. |

### CONF-035: Dynamic Pricing Formula Evaluation (Deterministic)

| Field | Value |
|-------|-------|
| **Layer** | Economy |
| **Tier** | Full |
| **Spec Sections** | §19.4, §19.15.3 |
| **Preconditions** | Context with dynamic pricing formula. |
| **Steps** | 1. Set metrics: `MemberCount = 50`, `ContextMessageRate = 10`. 2. Evaluate `PricingFormula` with `Linear` variable. 3. Verify: `cost = base_cost + (coefficient * metric / 1,000,000)`. 4. Verify cap and floor constraints. |
| **Expected Outcome** | Formula evaluation is deterministic. Two implementations produce identical costs for identical inputs. |

## 26.11 Bridge Tests (§12)

### CONF-036: Bridge Registration and Approval

| Field | Value |
|-------|-------|
| **Layer** | Bridge |
| **Tier** | Full |
| **Spec Sections** | §12.2.1, §12.12 |
| **Preconditions** | Context with governance that can approve bridges. |
| **Steps** | 1. Submit `BridgeRegistrationRequest`. 2. Governance votes to approve. 3. Bridge status changes to `Active`. 4. Bridge appears in context metadata `bridges` field (§5.7). |
| **Expected Outcome** | Registration event in event log. Bridge visible in metadata. Status is `Active`. |

### CONF-037: Shadow Identity Creation and Claiming

| Field | Value |
|-------|-------|
| **Layer** | Bridge |
| **Tier** | Full |
| **Spec Sections** | §12.3, §12.12.3, §12.12.4 |
| **Preconditions** | Active bridge in context. |
| **Steps** | 1. Bridge creates shadow identity for platform user. 2. Shadow has `provenance_status: Shadow`. 3. Platform user creates SCP identity and attestation. 4. User submits `ClaimRequest` with attestation proof. 5. Claim validation hash computed (domain: `"SCP-CLAIM-V1:"`). 6. Shadow status changes to `Claimed`. |
| **Expected Outcome** | Shadow created. Claim succeeds. Provenance status updated. Event log records both events. |

### CONF-038: Bridged Message Provenance Marking

| Field | Value |
|-------|-------|
| **Layer** | Bridge |
| **Tier** | Full |
| **Spec Sections** | §12.5, §12.12.5 |
| **Preconditions** | Active bridge with shadow identity. |
| **Steps** | 1. Bridge relays message from platform user. 2. Message includes `BridgeProvenance` with platform, bridge ID, mode, shadow status. 3. Recipients verify provenance. 4. `BridgeTrustLevel` is `ShadowBridged` (lowest). |
| **Expected Outcome** | Message carries correct provenance. Trust level is distinguishable from native messages. |

## 26.12 Interop Scenarios (Cross-Cutting)

### CONF-039: Two Implementations Exchange Messages

| Field | Value |
|-------|-------|
| **Layer** | Interop |
| **Tier** | Core |
| **Spec Sections** | §9.5, §9.8, §9.10, §9.16 |
| **Preconditions** | Implementation A and Implementation B both in the same MLS group. |
| **Steps** | 1. A sends message (sign, encrypt, pad, wrap). 2. B receives, unwraps, unpads, decrypts, verifies signature. 3. B sends reply. 4. A receives and processes. |
| **Expected Outcome** | Bidirectional messaging works. Signatures verify cross-implementation. Padding/unpadding is compatible. Sender key encryption/decryption is compatible. |

### CONF-040: Cross-Implementation Context Join

| Field | Value |
|-------|-------|
| **Layer** | Interop |
| **Tier** | Core |
| **Spec Sections** | §5.3, §9.7 |
| **Preconditions** | Implementation A created context. Implementation B has a DID. |
| **Steps** | 1. A generates MLS Welcome for B. 2. B processes Welcome (MLS KeyPackage, group info). 3. B joins MLS group. 4. B sends a message. 5. A decrypts B's message. |
| **Expected Outcome** | Cross-implementation MLS interop works. Welcome processing succeeds. Group state converges. |

### CONF-041: Mixed-Implementation Governance Vote

| Field | Value |
|-------|-------|
| **Layer** | Interop |
| **Tier** | Full |
| **Spec Sections** | §6.4 |
| **Preconditions** | Context with member A (Implementation 1) and member B (Implementation 2). |
| **Steps** | 1. A proposes governance action. 2. B votes approve (signed per `"SCP-VOTE-V1:"`). 3. A verifies B's vote signature. 4. Proposal passes. |
| **Expected Outcome** | Vote signature produced by Implementation 2 is verifiable by Implementation 1. Canonical hash construction is interoperable. |

### CONF-042: Cross-Implementation Sync Recovery

| Field | Value |
|-------|-------|
| **Layer** | Interop |
| **Tier** | Full |
| **Spec Sections** | §23 |
| **Preconditions** | Implementation A and B in same context. B goes offline for > 4 hours. |
| **Steps** | 1. B reconnects. 2. B requests snapshot from A. 3. A generates snapshot. 4. B applies snapshot. 5. B applies deltas. 6. B's MLS state matches A's. |
| **Expected Outcome** | Snapshot format is interoperable. Delta replay works cross-implementation. MLS state converges. |

## 26.13 Core vs Full Conformance

### SCP Core Conformance (Minimum for Interoperability)

Tests: CONF-001 through CONF-021, CONF-023, CONF-027, CONF-028, CONF-039, CONF-040.

An implementation that passes all Core tests can:
- Create and manage identities
- Create and join contexts
- Send and receive encrypted messages
- Perform governance operations
- Recover from offline periods
- Interoperate with other Core-conforming implementations

### SCP Full Conformance

Tests: All CONF-001 through CONF-042.

An implementation that passes all Full tests additionally supports:
- UCAN delegation chains and revocation
- Discovery protocol (handles, agent search, push notifications)
- Economic governance (cost schedules, payments, dynamic pricing)
- Bridge protocol (registration, shadows, claiming, provenance)
- Multi-relay operation
- Cross-implementation sync and governance

## 26.14 Conformance Reporting

A conformance report MUST include:

| Field | Description |
|-------|-------------|
| Implementation name | Name and version of the implementation being tested. |
| Protocol version | SCP protocol version targeted (v1 for this suite). |
| Test date | Date of the conformance run. |
| Tier | Core or Full. |
| Results | Pass/fail for each test ID. |
| Failures | For each failed test: test ID, step that failed, observed vs expected behavior. |
| Environment | OS, runtime version, cryptographic library versions. |

Conformance reports SHOULD be published alongside the implementation for community verification.