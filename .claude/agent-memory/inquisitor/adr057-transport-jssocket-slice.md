---
name: adr057-transport-jssocket-slice
description: ADR-057 browser relay transport slice — MLS-keyed pseudonym + announce mesh. Verdict UNSOUND on announce-timing (real-relay delivery gap masked by test harness).
metadata:
  type: project
---

# ADR-057 in-browser relay transport slice (branch feat/adr057-transport-jssocket)

Reviewed the #1980-independent browser relay transport slice (scp-client / scp-client-wasm /
scp-mls). Four decisions interrogated.

**Why (motivation):** browser participant driver over shared scp-mls; wire real §9.10.4
per-context-pseudonym fan-out + injected JsSocket. Governed by ADR-057 Amendment 2026-07-16
(Option A) + planning-session-10.

**How to apply / verdicts:**

- **Serde private-seed extraction (`scp-mls/group.rs::extract_ed25519_seed`) — SOUND, not DOA.**
  openmls_basic_credential 0.5 `SignatureKeyPair::private()` IS `#[cfg(feature="test-utils")]`;
  no non-test getter exists (`from_raw` is public but write-only). Serde is the only public read
  path — premise TRUE. NOT new fragility: `snapshot.rs::ProviderSignerDump` already round-trips
  the whole signer via `rmp_serde::to_vec_named`/`from_slice`, so an openmls serde-shape bump
  breaks snapshot/restore regardless; the derive_pseudonym cross-check test fails loudly too.
  Alternative (generate seed in scp-mls via ed25519-dalek + `from_raw`, retain it) exists but
  holds a SECOND long-lived seed copy — worse for keys-on-device. Serde approach defensible.

- **MLS-keyed pseudonym (A1 / Option A) — SOUND interim, artifact-flow CORRECT.** Verified
  `classify_pseudonym_announcement` (scp-protocol/context/pseudonym.rs) NEVER re-derives a peer's
  expected pseudonym — validates tag/sender-match/reserved/collision only, accepts the
  authenticated announced value. So MLS-keyed browser pseudonyms pass native validation; the
  device-local-announce premise holds. Signature key is STABLE across PCS self_update
  (LeafNodeParameters set extensions only, same signer reused) — only explicit identity-key
  rotation changes it, symmetric to native §9.12. Spec 09-security-model.md + ADR amended DOWN to
  record the human-ruled deviation (2026-07-17) BEFORE code — textbook provenance, not phantom.
  "Resolves with #1980" is a VALID deferral (identity key genuinely not in wasm; Signer trait
  exposes only did()/signing_key_id()). Value changes at #1980 but only the key SOURCE — wire
  format/algorithm/announce model permanent; re-announce absorbs it. Not DOA.

- **API: socket required + send_message ()→ instead of Vec<u8> — SOUND.** Matches
  signer/storage/clock injection; no silent default. Old Vec<u8> return was an explicit MVP
  scaffold ("no relay in the MVP; bytes handed to receive_message by the test harness"). Removing
  it = de-scaffolding, correct. Minor: lone-member no-op returns same Ok(()) as a real fan-out.

- **★ Announce-timing deviation — UNSOUND / BLOCKER. Real-relay delivery gap masked by tests.**
  Coder moved announce from create_context to join/add/bystander-add (epoch-decryptability
  rationale is correct). BUT introduced a delivery-ordering gap: driver `subscribe()` hardcodes
  `ClientMessage::Subscribe{since:None}`; relay (webtransport/session.rs ~L534) backfills ONLY
  when `since:Some`. Existing members re-announce at the membership-change point — BEFORE the
  joiner processes its Welcome and subscribes — so with no backfill the joiner PERMANENTLY misses
  every announcement published before it subscribed. Result: joiner's `peer_pseudonyms` stays
  empty for pre-existing members → joiner→peer `send_message` returns PseudonymRegistryEmpty
  forever. Breaks even a stable 2-party context (asymmetric: creator learns joiner, joiner never
  learns creator). No reciprocal re-announce on receiving an announcement (ingest Accept just
  records). Tests pass ONLY because `tests/common/mod.rs::route_publishes` drains ALL captured
  frames and delivers them regardless of subscribe timing — a loopback with no subscription
  semantics, masking the gap. Fix at root: either subscribe with backfill (`since`=ctx-creation)
  OR add reciprocal announce (on Accept of a peer's announcement, re-announce own). This is the
  "dev/test stand-in masks a missing production guarantee" class.
