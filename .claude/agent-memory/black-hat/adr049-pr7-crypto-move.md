---
name: adr049-pr7-crypto-move
description: Attack surfaces in ADR-049 PR-7 (per-context MLS crypto moved to actor + §9.16.2 sender-key request/answer)
metadata:
  type: project
---

# ADR-049 PR-7 (feat/adr049-pr7-atomic-crypto-move) attack surfaces

Moves per-context MLS crypto onto the actor's `ContextCryptoState`; wires §9.16.2
sender-key PULL request/ANSWER + join-time push into production `decrypt_and_dispatch`.

## HIGH (latent) — confused-deputy: block/membership gate on self-asserted field
- `handle_sender_key_request` (state.rs ~1978-2002) gates MEMBERSHIP and BLOCKED
  on `request.requester_did` (a field INSIDE the signed payload), NOT the
  MLS-authenticated `sender_did`.
- Production caller `decrypt_and_dispatch` KeyRequest branch (messaging_helpers.rs
  3110-3145) resolves `requester_pk` from MLS `sender_did`, verifies the sig with
  it, but NEVER checks `sender_did == request.requester_did`.
- Sig hash includes requester_did but is verified with sender_did's key → a member
  M can set requester_did = ANY other member. Today harmless (blocked set is empty,
  response = responder's own key, M is a member). WHEN blocking is wired, a blocked
  M bypasses the block by naming an unblocked member. Fix now: gate on sender_did.

## MEDIUM — pull ANSWER wire-format mismatch (shipped, breaks §9.16.2 fallback)
- `handle_sender_key_request` returns a BARE `SenderKeyResponse` (state.rs 2030).
- Push path wraps in `SenderKeyDistributionMessage::KeyResponse` (state.rs 2583).
- Receiver `decrypt_and_dispatch` parses `SenderKeyDistributionMessage::from_bytes`.
- PR-7 routes the bare-response answer through pending_distributions → drain →
  broadcast to context_routing_id → every recipient decode-errors. Pull recovery
  path (join fallback) is non-functional as shipped. Requester side deferred (#2049)
  so latent, but a crafted request causes decode-error deliveries at all members.

## MEDIUM — nonce_dedup is Class-C (coalesced) → crash-window replay farm
- `nonce_dedup` lives in ContextCryptoState (Class-C best-effort persist).
- REQUEST_FRESHNESS_SECS = NONCE_EXPIRY_SECS = 300s. A crash before the coalescing
  window rolls back the nonce record; a relay replays a still-fresh (≤5min) request
  → fresh re-answer + re-broadcast. Bounded, no confidentiality break (answer sealed
  to requester ephemeral key). Amplification/DoS only.

## MEDIUM — no rate limit on inbound KeyRequest answer (member amplification)
- Every distinct fresh signed request → HPKE seal + MLS encrypt + broadcast to
  context_routing_id (all members). nonce_dedup only stops identical replays. No
  velocity gate on management msgs. Member already has send access → incremental.

## LOW — testing-gated commands
- HandleSenderKeyRequest/LandSenderKeyResponse/InspectIncomingInner all
  `#[cfg(feature="testing")]`. Sole prod-exclusion is the cfg feature (no runtime
  guard) — same class as TestAdapter. If `testing` compiled into a shipped bridge:
  InspectIncomingInner = decrypt-without-anti-replay oracle on actor's OWN context
  (no sibling reach) that advances the MLS decryption ratchet (repeat → recv desync).
- LandSenderKeyResponse keys the Class-M floor gate on CALLER-supplied context_id but
  installs to the actor's OWN store → context-confusion if they differ. Testing-only.

## What resists (verified sound)
- `sender_did` in OpenResult::Management is MLS-authenticated (decrypt_with_sender_did).
  Non-members/removed members can't reach the answer path (MLS wrap gate).
- KeyResponse push install: response.sender_did must == MLS sender_did; epoch gated
  per-sender in Class-M registry → M can only advance its OWN key.
- One-way take: taken_context_ids guard; provider twins fail-closed "owned by actor";
  wrapping keypair is node-global (process_incoming_sender_key unaffected).
- execute_add_member: full Class-S rollback chain on add/distribute/drain failure;
  seal targets member_wrapping_keys[member_did] (correct recipient); missing wrapping
  key → local-only, recoverable via pull (no strand, no wrong-recipient leak).
