# Crypto Agent Memory

Index only. Open a linked file for detail. One line per entry, under ~200 chars.
Keep this file under 140 lines: past line 200 it silently truncates on load.

## Constructions — signing preimages and verifiers

- [custody-violation-signing](custody-violation-signing.md) — issue #2335 finding 11 FIXED: §9.5.1 preimages + Ed25519 verifiers, Verified* newtypes (private verify fns, no Deserialize), `violation_reference` = violation signing hash as `[u8;32]`, CategoryARejection carries the layer-3 record, §25.25 Vectors 38/39
- [adr039-persona-and-signing](adr039-persona-and-signing.md) — `#active`/`#agent` is inside the signed InnerEnvelope preimage (SOUND); KeyResolver widened; production resolver still returns None for every (DID,kid)
- [HPKE RFC 9180 conformance](hpke-rfc9180-conformance.md) — custom-ECIES finding FIXED: one hand-implemented RFC 9180 core in scp-protocol/src/crypto/hpke.rs (A.1 KAT + hpke-rs oracle), custody Decap variant, 60→48 wire
- [event-log-and-canonical-hashing](event-log-and-canonical-hashing.md) — RFC 6962 separation, `hash_pair()` triplicated, open canonical-hash weaknesses, SCP-126 pruning defects, signed context export, PseudonymAnnounced removal
- [Event-log unification Phase 2](eventlog-unification-phase2.md) — ADR-011 runtime onto RFC 6962 substrate; truncation forgery CLOSED; §9.9.3 equivocation dedup; round-4 APPROVE

## Audits and reviews

- [spec-audit-findings](spec-audit-findings.md) — 9 CRITICAL / 11 HIGH / 8 MEDIUM / 5 LOW across specs 09, 03, 07. BroadcastEnvelope is the only signature with no domain separator; canonical serialization for signed structures missing entirely
- [ffi-bridge-crypto-audits](ffi-bridge-crypto-audits.md) — scp-ffi bridge layer 2026-02-28 and PR #127; CRITICAL UniFFI `ucan_revoke` revokes by token_id, not content-hash CID, so mobile/desktop revocations are no-ops
- [reviews-2026-q1](reviews-2026-q1.md) — bridge relay auth PR #255, Phase 0/1 readiness, white-paper review, economy pricing SCP-157, adapter credentials SCP-162
- [platform-adapters-and-pseudonym-parity](platform-adapters-and-pseudonym-parity.md) — Rust/Kotlin/Swift produce three DIFFERENT pseudonyms for one identity+context; unify per SCP-214
- [scp1717-pre-rotation-custody](scp1717-pre-rotation-custody.md) — round-10 SOUND; open: verify_migration does not bind old_document to old_did; CallbackKeyCustody import unsupported; step-7 publish failure has no recovery handle

## Open blockers and in-flight work

- [#1900 PR-2b WASM engine-adoption BLOCKER](pr2b-wasm-engine-adoption-blocker.md) — "transient engine + replay stored votes" not implementable: PR-2a added keyless ingest_approve/reject only, no keyless propose/seed. Unblock = `TrustedVoteIngest::ingest_proposal` (PR-2a-bis). Items A/B/C/D/H unblocked; E/F/G blocked
- [adr-051-prerotation-substrate](adr-051-prerotation-substrate.md) — ADR-051 pre-rotation custody substrate isolation (Proposed); separate-provider model sound per spec §9.7.4.1 §3
- [trust-ucan-classification](trust-ucan-classification.md) — TS `evaluateTrust` UCAN error → CapabilityValidation classification; fail-closed analysis; faithful port of the reviewed Python layer
- [nonce-dedup-saga-removal](nonce-dedup-saga-removal.md) — NonceDedup configurable-TTL API removed in lockstep with cross-context saga deletion; no replay regression; Python parity confirmed

## Reference

- [key-files](key-files.md) — where each construction lives: Merkle log, envelopes, sender keys, UCAN, custody, bridges, identity
- Randomness: production uses OsRng through `KeyCustody`; tests use `thread_rng()`. Detail in [adr039-persona-and-signing](adr039-persona-and-signing.md)
- DID formats: `did:dht:z<z-base-32>` in production, `did:key:<hex>` in tests (non-standard, and claiming.rs's form does not conform to W3C did:key)

## Build gotchas

- `cargo test -p scp-event-log` alone fails 116 tests — hex `did:key` sits behind the scp-primitives `testing` feature (identity.rs:118). Run with `--features testing`
- Concurrent agents share this worktree. A broken build in `trust/attestation.rs` or `identity/attestation.rs` is usually another agent mid-edit, not your change — poll `cargo check` rather than editing files you do not own
