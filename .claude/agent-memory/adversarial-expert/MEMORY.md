# Adversarial Expert — Agent Memory

SCP threat-model checklist. Each item names a place a past review found a real gap.

## Relay (untrusted store-and-forward)
- A relay can drop messages, reorder them within an epoch, forge metadata, and observe timing and routing patterns.
- A relay cannot read content (two encryption layers), replay a message to the same recipient (the MLS generation counter rejects it), or forge inner content (Ed25519 inner signature).
- Check that every checkpoint comparison verifies the checkpoint signature, and that clients check `blob_id == SHA-256(blob)` themselves.
- Check every use of relay-supplied metadata (`stored_at`, `blob_ttl`) in reconnection logic; the relay can forge it.

## Compromised member
- Forward secrecy needs both the MLS epoch ratchet and the deletion of old keys. Check grace windows, and check that `destroy_group` zeroizes key material rather than only freeing it.
- A member cannot forge another member's message (MLS membership tag plus inner signature), and the UCAN validation pipeline blocks capability escalation.

## Cross-context isolation
- The MLS group ID, the inner-envelope hash, pseudonym derivation, and UCAN validation each bind `context_id`. Look for a hash or signature preimage that omits `context_id`; key-request hashes omitted it once.

## Metadata leakage
- The relay sees bucket sizes, `routing_id`, `recipient_hint`, timing, and SUBSCRIBE patterns. A routing identifier that a non-member can compute from public data lets that party enumerate membership, so a routing identifier must derive from a key only members hold.
- The recurring spec defect: a section states intent and leaves the bytes undefined (no canonical encoding for a signature preimage, no nonce format, no wire format). Ask for the exact bytes.
