# A DID String Encodes an Identity Key, Which Verifies No Content Signature

## Problem

`scp_did::extract_public_key_from_did` decodes a `did:dht:z<z-base-32>` string into
a 32-byte Ed25519 public key that string encodes. That key is an Identity Key —
verification method `#0`. ADR-039's key-property table marks `#0` "Signs operational
actions: No", and §9.7.4 of a security-model spec confines it to DID document updates
plus pre-rotation commitments.

`scp_event_log::tree::verify_event_signature` called that function and verified every
event signature against whatever it returned. Two consequences followed:

1. **A key an actor never signs content with became the only accepted key.** Every
   event a conforming signer produced with `#active` or `#agent` failed, and only a
   signature by a hardware-held `#0` passed.
2. **A rotation changed nothing a verifier read.** A DID string never changes when a
   participant rotates `#active` or `#agent` (§9.7.4, "The DID string does NOT change"),
   so a verifier recovering its key from that string reads the same key before and after
   every key event an owner ever performs — including a removal, which is the one act
   §9.12 defines as revocation.

`BridgeDidResolver` in `crates/scp-ffi/common/src/resolvers.rs` collapses `#active` onto
that same function, so this is a class rather than one site. That resolver still does it:
`resolve_public_key` returns `extract_public_key_from_did(did)`, and
`DispatchDidResolver::new` selects it whenever a bridge instance has not run
`identity_create`. See Affected Files below for why this branch left it.

## Why It Matters

A DID string is a *self-certifying identifier*: it commits to one key so a resolver can
check that a DID document, published over an untrusted relay or DHT, belongs to that
DID (§3.8, §9.6.1). Recovering a key from a DID string answers exactly that question —
checking a BEP44 signature over a DID document, or checking that a DID string is
canonical.

Verifying a *content* signature asks a different question. A content signature names an
operational key a participant may rotate or remove, and only a resolved DID document
says which methods a participant still publishes. §23.13 paragraph 1 of a sync spec
states this rule for an event, and §9.5.2 of a security-model spec carries
`signing_key_id` (`#active` or `#agent`) inside every other signed structure for that
same reason.

## The Rule a Resolved Document Then Supplies

Reading a document is the first half. The second half is knowing which of its methods a
given duty accepts, and the two duties take opposite answers.

**A live-decision path binds to the current key only.** §3.11.4 steps 7 and 8 of the
identity spec authenticate a session happening now, and §9.7.1 check 1 of the
security-model spec verifies a KeyPackage attestation, which is a bearer capability a
holder presents now. Both accept `#active` and `#agent` and nothing else. In code, both
reach a key through `DidDocument::signing_key_for`, which takes a two-variant
`SigningKeyId` and then requires a relationship array to reference the named method.

**A content path accepts a retired key.** An event-log leaf records what an actor did at
the sequence it occupies, so a later rotation must not retroactively unmake that
authorship. §23.13 paragraph 1 therefore has a verifier accept a `#retired-{n}` or
`#retired-agent-{n}` method the resolved document still carries. In code, that path
reaches those keys through `DidDocument::historical_assertion_keys`.

**Rotation is soft; removal is hard.** ADR-003, DID creation, item 4a retains a rotated
key under a `#retired-*` identifier, and that retained key keeps verifying content
indefinitely. §9.12 of the security-model spec assigns compromise recovery to *removing*
the method from `verificationMethod` entirely, and a method a document no longer carries
verifies nothing, at any sequence, for any reader. An owner who reaches for a hygiene
rotation to handle a compromise leaves the compromised key able to sign event-log leaves
that every honest verifier accepts.

**No DID-document field records compromise.** A `Compromised { from: N }` marker was
considered and rejected. Nothing in an SCP record carries the DID-document sequence a
reader would compare against `N`: ADR-011 acceptance criterion 1 gives `Event` a Unix
`timestamp` and a per-log `sequence` and no DID-document sequence, whoever holds the key
writes that `timestamp`, and §9.14 confines a timestamp to ordering hints and
replay detection rather than security-critical decisions. Presence in
`verificationMethod` is the whole test.

## Correct Approach

- Resolve a signer's DID document, then read a verification method that document names.
  Never recover a key from a DID string for this purpose.
- Decide which duty the call site performs before choosing a resolver. A live
  authentication or a bearer capability calls `signing_key_for`. A content signature
  calls `signing_key_for` for the current keys and `historical_assertion_keys` for the
  retired ones.
- **Do not gate a historical-verification path on `assertionMethod` membership.**
  `DidDocument::retire_active_key` rebuilds `authentication` and `assertion_method` as
  `#active` plus `#agent`, so a retired method is referenced by neither array and a
  relationship gate finds nothing there. `historical_assertion_keys` gates on three
  facts a rotation leaves intact instead: an identifier equal to `{document.id}#retired-{n}`
  or `{document.id}#retired-agent-{n}` carried exactly once, with `{n}` the decimal
  rendering of a `u64` and no leading zero; a `type` of `Ed25519VerificationKey2020`; and
  a `controller` equal to the document's own DID.
- Reject `#0` on every content and authentication path. It signs no operational action.
- Match a whole verification-method identifier, never a `#fragment` suffix. Suffix
  matching lets `did:dht:zSOMEONEELSE#active`, sitting inside a victim's document,
  answer a lookup for `#active`.
- Report a holder, not a fragment. `verify_event_signature` answers `SigningKeyId::Active`
  for a `#retired-{n}` method and `SigningKeyId::Agent` for a `#retired-agent-{n}` method,
  because a rotation moves a key between identifiers without moving it between holders,
  and ADR-039's accountability argument rests on keeping the two holders apart.
- Fail closed when resolution fails. Never fall back to a DID-string key under any
  condition; that fallback is this defect.
- Keep resolution outside a leaf crate that must stay wasm-safe. `scp-event-log` cannot
  depend on `scp-identity` (ADR-057 crate topology), so its verification functions take
  a `&DidDocument` a caller already resolved — a shape
  `scp_mls::credential::ScpCredential::resolve_signing_key` and
  `scp_event_log::checkpoint::verify_checkpoint_signature` both use.
- State plainly what a caller still owes. A leaf crate cannot check document freshness.
  A document cached before a *rotation* costs a caller nothing, because the retired key
  verifies either way. A document cached before a *removal* is what a stale caller pays
  for, so removal revokes a key exactly as fast as a caller re-resolves.

## How to Spot It

Every call of `extract_public_key_from_did` outside DID-document self-certification and
DID-string canonicality is a candidate. Ask what a recovered key is about to verify: a
DID document (correct), or a message, event, attestation, or token a participant signed
(wrong — resolve a document instead).

The second smell is a resolver whose gate does not match its duty. A live-authentication
path that reaches `historical_assertion_keys` admits a key an owner rotated away. A
content path that gates on `assertionMethod` membership finds no retired method and
rejects authorship a rotation was never meant to unmake.

## Affected Files

- `crates/scp-event-log/src/tree.rs` — `verify_event_signature`, fixed by verifying
  against a caller-resolved DID document, and by accepting a retired method for content.
- `crates/scp-did/src/document.rs` — `verification_method_by_fragment` and its
  `#agent` siblings, fixed by matching a whole identifier;
  `historical_assertion_keys` and `remove_verification_method`, which supply the soft
  and hard halves of the rule.
- `crates/scp-ffi/common/src/resolvers.rs` — `IdentityBackedDidResolver::extract_public_key`,
  fixed by taking a `SigningKeyId` and calling `signing_key_for`. The sibling
  `BridgeDidResolver::resolve_public_key` in the same file is unfixed: it returns the
  DID-string `#0` key, and its `resolve_public_key_by_kid` inherits a trait default that
  routes `SigningKeyId::Active` to that same key. Every bridge reaches it: all three
  `DispatchDidResolver::new` call sites — `crates/scp-ffi/src/ucan.rs`,
  `crates/scp-ffi/napi/src/ucan.rs`, `crates/scp-ffi/uniffi/src/bridge.rs` — select
  `BridgeDidResolver` whenever a bridge instance has not run `identity_create`. The
  branch `origin/fix/ffi-resolvers-blockers-r1-r5` deletes both `BridgeDidResolver` and
  `DispatchDidResolver`; no open pull request carries that branch yet, and nobody has
  decided whether the deletion or a fail-closed `BridgeDidResolver` is the fix. This
  branch left it because Alec scoped this change to the event-log verifier, the bridge
  login of `verify_bridge_jwt`, and the `IdentityBackedDidResolver` UCAN path.
- `crates/scp-node/src/bridge_auth.rs` — `verify_bridge_jwt`, fixed by decoding the
  `kid` header through `SigningKeyId::from_fragment` and calling `signing_key_for`
  against `authentication`, with no fragment-string fallback.
- `crates/scp-protocol/src/trust/attestation.rs` —
  `IdentityDidPublicKeyResolver::resolve_public_key`, which verifies attestation
  signatures against `#0` while §9.5.2 and §3.5.2 say `#active` or `#agent` signs an
  attestation. Unfixed; a fix needs a ruling on ADR-017 versus §9.5.2.
- `crates/scp-protocol/src/bridge/claiming.rs` — claimant and attestation-issuer key
  recovery, same class, unfixed.

## Found In

Review of `scp_event_log::tree::verify_event_signature`, August 2026. The hard/soft rule
above corrects what this lesson first recorded: it claimed a retired fragment verifies
nothing, which is right for a live authentication and a KeyPackage attestation and wrong
for a content signature.
