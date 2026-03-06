# Adversarial Expert — Agent Memory

## SCP Threat Model — Evergreen Patterns

### Relay Threat Surface
Relay is untrusted store-and-forward. Key gaps to always check:
- Checkpoint signature verification (does `compare_checkpoint` actually verify?)
- Client-side blob_id verification (clients must check `blob_id == SHA-256(blob)`)
- Relay-provided metadata used for reconnection logic (stored_at, blob_ttl)
- Relay can: drop messages, reorder within epoch, forge metadata, observe timing/routing patterns
- Relay cannot: read content (double encryption), replay to same recipient (MLS generation), forge inner content (Ed25519)

### Compromised Member Threat
- Key retention: check grace windows and whether destroy_group actually zeroizes
- Forward secrecy depends on MLS epoch ratchet AND actual key deletion
- Members cannot forge other members' messages (MLS membership tag + inner signature)
- UCAN capability escalation blocked by validation pipeline

### Cross-Context Isolation
- MLS group ID prevents cross-context replay
- Inner envelope hash, pseudonym derivation, UCAN validation all bind to context_id
- Watch for functions that omit context_id from their hash (e.g. key request hashes)

### Metadata Leakage
- Bucket sizes, routing_id, recipient_hint, timing, SUBSCRIBE patterns all visible to relay
- CRITICAL: Public-key HMAC for pseudonyms means any party knowing a DID can compute all pseudonyms
- Metadata routing_id = SHA-256(context_id || "scp-metadata") enables membership enumeration
- Bucket size contradiction: §9.10.3 vs §9.10.6

### ADR Completeness Audit (2026-03-05) — 47 Findings
- 3 CRITICAL, 10 HIGH, 22 MEDIUM, 12 LOW
- See detailed report in conversation history
- CRITICAL: (1) Inner envelope sig preimage no canonical encoding, (2) Public-key HMAC defeats pseudonym unlinkability, (3) Nonce format contradiction mint vs validate
- Key structural issues: cross-context transport undefined, CeilingPolicy::Governed contradicts ADR-009

### Spec Gaps — Cross-Section Inconsistencies (Sections 8/9/10 audit 2026-03-05)
- SenderKeyRequest signature scope not specified — no proof it binds context_id
- AccessKeyRequest 30s replay window conflicts with 5-minute clock skew tolerance (§9.14)
- Two different routing_id derivation schemes: SHA-256("scp:did:"||did) vs HMAC-SHA256 pseudonyms
- Block notification shown as JSON but rest of protocol uses MessagePack
- Event log pruning explicitly deferred — unbounded growth breaks device-as-node
- Push notification registration protocol completely missing
- Multi-device MLS key sharing declared "client-scope" but is fundamental protocol design
- QUIC 0-RTT anti-replay for non-idempotent PUBLISH unspecified

### Spec Gaps — §4/§5 Underspecification (2026-03-05)
- 48 findings: 4 CRITICAL, 16 HIGH, 20 MEDIUM, 8 LOW
- CRITICAL: (1) No state machine in §5, (2) No invitation bundle wire format, (3) Relay can't validate encrypted membership for child context eligibility, (4) BroadcastEnvelope AES-GCM nonce unspecified
- BroadcastEnvelope content_hash is a plaintext confirmation oracle (HIGH)
- Core pattern: design docs not protocol specs — intent clear, bytes undefined
- See detailed report: [spec-underspec-04-05.md](spec-underspec-04-05.md)
