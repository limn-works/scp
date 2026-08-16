# A DID String Encodes an Identity Key, Which Verifies No Content Signature

## Problem

`scp_did::extract_public_key_from_did` decodes a `did:dht:z<z-base-32>` string into
a 32-byte Ed25519 public key that string encodes. That key is an Identity Key —
verification method `#0`. ADR-039's key-property table marks `#0` "Signs operational
actions: No", and §9.7.4 of a security-model spec confines it to DID document updates
plus pre-rotation commitments.

`scp_event_log::tree::verify_event_signature` called that function and verified every
event signature against whatever it returned. Two consequences followed:

1. **Rotation stopped mattering.** A DID string never changes when a participant
   rotates `#active` or `#agent` (§9.7.4, "The DID string does NOT change"). A verifier
   recovering its key from that string therefore accepts a signature from a key that
   participant retired years earlier, and rejects a signature from a key that
   participant holds now.
2. **A key barred from operational signing became a sole accepted key.** Every event a
   conforming signer produced with `#active` or `#agent` failed, and only a signature
   by a hardware-held `#0` passed.

`BridgeDidResolver` in `crates/scp-ffi/common/src/resolvers.rs` collapsed `#active`
onto that same function, so this is a class rather than one site.

## Why It Matters

A DID string is a *self-certifying identifier*: it commits to one key so a resolver can
check that a DID document, published over an untrusted relay or DHT, belongs to that
DID (§3.8, §9.6.1). Recovering a key from a DID string answers exactly that question —
checking a BEP44 signature over a DID document, or checking that a DID string is
canonical.

Verifying a *content* signature asks a different question. A content signature names an
operational key a participant may rotate, and only a resolved DID document says which
key that is right now. §23.13 paragraph 1 of a sync spec states this rule for an event,
and §9.5.2 of a security-model spec carries `signing_key_id` (`#active` or `#agent`)
inside every other signed structure for that same reason.

## Correct Approach

- Resolve a signer's DID document, then read a verification method that document names.
  `#active` first, then `#agent` — ADR-050 §Signer states that order for signing.
- Accept no other fragment. `#0` signs no operational action, and `#retired-{n}` /
  `#retired-agent-{n}` are fragments `DidDocument::retire_active_key` and
  `DidDocument::rotate_agent_key` assign to a key a participant already retired.
- Match a whole verification-method identifier, never a `#fragment` suffix. Suffix
  matching lets `did:dht:zSOMEONEELSE#active`, sitting inside a victim's document,
  answer a lookup for `#active`.
- Check three document facts before trusting a key: a method declares type
  `Ed25519VerificationKey2020`, names its own DID as controller, and appears in
  `assertionMethod` (W3C DID Core §5.3.3).
- Fail closed when resolution fails. Never fall back to a DID-string key under any
  condition; that fallback is this defect.
- Keep resolution outside a leaf crate that must stay wasm-safe. `scp-event-log` cannot
  depend on `scp-identity` (ADR-057 crate topology), so its verification functions take
  a `&DidDocument` a caller already resolved — a shape
  `scp_mls::credential::ScpCredential::resolve_signing_key` and
  `scp_event_log::checkpoint::verify_checkpoint_signature` both use.
- State plainly what a caller still owes. A leaf crate cannot check document freshness,
  so rotation revokes a key exactly as fast as a caller re-resolves. Say so in a doc
  comment instead of claiming rotation takes effect on publication.

## How to Spot It

Every call of `extract_public_key_from_did` outside DID-document self-certification and
DID-string canonicality is a candidate. Ask what a recovered key is about to verify: a
DID document (correct), or a message, event, attestation, or token a participant signed
(wrong — resolve a document instead).

## Affected Files

- `crates/scp-event-log/src/tree.rs` — `verify_event_signature`, fixed by verifying
  against a caller-resolved DID document.
- `crates/scp-did/src/document.rs` — `verification_method_by_fragment` and its
  `#agent` siblings, fixed by matching a whole identifier.
- `crates/scp-ffi/common/src/resolvers.rs` — `BridgeDidResolver::resolve_public_key`,
  which branch `fix/ffi-resolvers-blockers-r1-r5` addresses.
- `crates/scp-protocol/src/trust/attestation.rs` —
  `IdentityDidPublicKeyResolver::resolve_public_key`, which verifies attestation
  signatures against `#0` while §9.5.2 and §3.5.2 say `#active` or `#agent` signs an
  attestation. Unfixed; a fix needs a ruling on ADR-017 versus §9.5.2.
- `crates/scp-protocol/src/bridge/claiming.rs` — claimant and attestation-issuer key
  recovery, same class, unfixed.

## Found In

Review of `scp_event_log::tree::verify_event_signature`, August 2026.
