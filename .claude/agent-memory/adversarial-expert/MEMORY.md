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
- Pseudonym derivation (HMAC) prevents sender identity correlation across contexts
