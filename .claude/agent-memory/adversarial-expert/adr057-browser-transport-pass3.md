---
name: adr057-browser-transport-pass3
description: ADR-057 browser relay transport — PASS 3 ship verdict + the S1-test-masking finding
metadata:
  type: project
---

# ADR-057 browser relay transport (feat/adr057-transport-jssocket) — PASS 3

Verdict: SHIP. The cleanup delta did NOT weaken fidelity.

**Mock extraction (`crates/scp-relay-mock/src/lib.rs`) is faithful.** Both load-bearing
properties preserved:
- self-echo to publisher: `RelayState::apply` Publish arm delivers to ALL subs INCLUDING
  publisher (lib.rs:350-359, no publisher exclusion).
- `since:None` no-backfill: Subscribe arm backfills only on `Some` (lib.rs:304-320).
Client only ever subscribes `since:None` (client.rs `subscribe`), so the mesh necessity
in `two_party_mesh_delivers_both_directions` is genuine, not masked by backfill.

**next_sequence → Result** (context.rs:173) is a correct fail-closed `checked_add`
nonce-reuse guard (§9.16 AEAD nonce input). No regression.

**Classifier centralization** (pseudonym.rs:236 `classify_pseudonym_announcement`, now
5-arg with `local_pseudonym`): semantically equivalent to old registry-augment, strictly
safer. Both callers updated (scp-client client.rs, scp-runtime messaging_helpers.rs:566).
S1 covered by REAL unit tests: pseudonym.rs:499 + messaging_helpers buffered_forged test.

**handle_relay_frame categorization** (client.rs ~1165): only swallows genuine decrypt
junk (Mls/SenderKey/Codec/ChannelContentMismatch/Driver). ContextPoisoned + StorageBackend
+ UnsupportedMembershipChange are DISTINCT variants → surface via `Err(e) => Err(e)`. Poison
guard fires at context_mut BEFORE decrypt. Safe.

## MINOR finding — mislabeled S1 integration test
`transport_regression.rs::forged_announcement_claiming_the_victims_own_pseudonym_is_rejected`
sends the forgery via `send_message` (app fan-out to Alice's pseudonym = App channel). An
announcement payload on the App channel hits the M-E ChannelContentMismatch drop BEFORE
reaching the classifier — so the test NEVER exercises the S1 `local_pseudonym` guard it
claims to. Deleting the S1 clause would not fail this test. Property is still covered by the
two unit tests above; this is test-fidelity, not a security gap. To truly exercise S1 the
forgery must be delivered on the announcement channel (context_routing_id).
