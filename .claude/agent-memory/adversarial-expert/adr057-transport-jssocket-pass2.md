---
name: adr057-transport-jssocket-pass2
description: PASS-2 verdict on ADR-057 browser relay transport self-echo/reciprocal-announce fix (branch feat/adr057-transport-jssocket @ 4c8afb284) — SHIP
metadata:
  type: project
---

# ADR-057 Browser Relay Transport — PASS 2 verdict: SHIP

PASS 1 was DO-NOT-SHIP (self-echoed announcement threw on every announce; loopback
harness structurally couldn't catch it). PASS 2 fix verified REAL, not re-masked.

**Why:** the fix is genuine and the new harness is faithful; empirically confirmed.
**How to apply:** if this branch resurfaces or native wires its relay-receive pump,
the self-echo/mesh logic is already correct in shared scp-mls/scp-client.

## Verified facts
- Self-echo IS a real shipped-relay property: `deliver_to_subscribers`
  (scp-transport/src/relay/subscription.rs:142) iterates ALL subscribers of a
  routing_id with NO publisher exclusion. Mock is faithful, not a strawman.
- Fix maps openmls `ValidationError::CannotDecryptOwnMessage` →
  `MlsError::CannotDecryptOwnMessage` at all 4 decrypt sites (scp-mls/encrypt.rs
  `classify_process_message_error`); parent d9ee4ed1e has ZERO occurrences (new).
  Client benign-drops it at receive_on_channel (client.rs ~1260), no persist.
- Reciprocal-announce guard is sound: `learned_new_peer =
  !peer_pseudonyms.contains_key(member_did)`, keyed on DID. classify step 2 binds
  `announcement.member_did == authenticated sender_did` (pseudonym.rs:236), so a
  member can only announce its OWN DID → one reciprocal per real member, no storm.
  Pseudonym rotation (same DID) does NOT retrigger. DID churn requires real MLS
  joins (add-Commits) → bounded, not an amplification primitive.
- Self-echo drop cannot censor legit frames: CannotDecryptOwnMessage is decided
  from encrypted sender_data (epoch-secret-protected) — relay can't forge it; a
  malicious member can only make its OWN crafted frame drop; the real frame from C
  is delivered independently. Relay can always drop (untrusted pipe) — no new power.
- Mock models: subscription table, deliver-to-all-incl-publisher, backfill on
  since:Some only (client always uses since:None → no backfill → mesh genuinely
  needed). pump() `.expect()`s handle_relay_frame → pre-fix panics loudly (the
  structural catch loopback lacked). 6/9 regression tests fail pre-fix (all that
  pump after an announcement), 3 pass — matches coder claim exactly.
- Tests assert DECRYPTED plaintext through the mock (first_received == bytes) for
  self-delivery, both-directions-2-party, and 3-party — not addressing.

## Gates
- scp-client transport_regression 9/9, full scp-client 71, scp-client-wasm 23,
  scp-mls 154 — all green native. wasm32 build gate passes. clippy clean.
- Residual (NOT blocker, pre-existing/documented): wasm32 runtime not executed
  (no wasm-bindgen-test-runner in env → native-host test only; compile-gated).
  Native parity latent (shared fix, no live native pump yet — honestly flagged).
  T4 self-certifying wrapping-key directory trusted from adder (§23.13 slice).
