# Crypto Agent Memory — index

One line per entry. Detail lives in the linked topic files.

## Constructions reviewed (by subsystem)

- [DID-record relay WRITE path (#482)](did-record-relay-write-path.md) — SOUND @781297f29; one `bep44_signable` preimage everywhere; `did_record_routing_id` single source for WRITE + relay admission; read path discards the frame pubkey.
- [Bridge relay auth + DID healing](bridge-relay-auth-did-healing.md) — `SCP-BRIDGE-REGISTER-V1` 63B fixed preimage SOUND; `DualLayerResolver` anti-rollback via cached seq; migration-proof concat ambiguity still open.
- [Merkle + canonical hashing](merkle-and-canonical-hashing.md) — RFC 6962 domain separation OK; CRITICAL: two incompatible attestation canonical forms (`claiming.rs` BE+prehash vs `trust/attestation.rs` LE+raw); pruning gaps (SCP-126).
- [Event-log review notes](event-log-review-notes.md) — signed context-export root binding (16a2cd42b) + `PseudonymAnnounced` removal (f438acf0f), both APPROVE; `-p scp-event-log` needs `--features testing`.
- [Event-log unification Phase 2](eventlog-unification-phase2.md) — ADR-011 runtime onto the RFC 6962 substrate; truncation forgery CLOSED; §9.9.3 equivocation dedup; round-4 APPROVE.
- [HPKE RFC 9180 conformance](hpke-rfc9180-conformance.md) — custom-ECIES finding FIXED; one hand-impl core in `scp-protocol/src/crypto/hpke.rs` (A.1 KAT + hpke-rs oracle); 60→48 wire; all 5 paths conformed.
- [FFI bridges, UCAN + ADR-039 persona](ffi-bridges-ucan-and-persona.md) — CRITICAL UniFFI `ucan_revoke` uses token_id not CID; ADR-039 `signing_key_id` is in the signed preimage (SOUND) but prod `KeyResolver` still returns None for all.
- [SCP-1717 pre-rotation custody](scp1717-pre-rotation-custody.md) — round-10 SOUND, no blockers; open MEDIUMs: callback `import_ed25519_signing_key` Unsupported, substrate isolation, step-7 no recovery handle.
- [ADR-051 pre-rotation substrate](adr-051-prerotation-substrate.md) — substrate isolation (Proposed); separate-provider model sound per spec §9.7.4.1 §3.
- [Platform adapters + pseudonyms](platform-adapters-and-pseudonyms.md) — Rust/Kotlin/Swift pseudonym derivations are MUTUALLY INCOMPATIBLE (Android uses the PUBLIC key as HMAC key); unify per SCP-214.
- [Phase 0/1 readiness, economy, white paper](phase01-readiness-economy-whitepaper.md) — sender-key msgpack SOUND; PRE-EXISTING HIGH: HPKE `info` lacks context/sender/epoch binding and AES-GCM has no AAD.
- [Trust UCAN classification (TS)](trust-ucan-classification.md) — `evaluateTrust` UCAN error → `CapabilityValidation`; fail-closed; faithful port of the reviewed Python layer.
- [Nonce-dedup / saga removal](nonce-dedup-saga-removal.md) — NonceDedup configurable-TTL API removed in lockstep with cross-context saga deletion; no replay regression; Python parity confirmed.

## Spec-level

- [Spec crypto audit findings](spec-audit-findings.md) — 9 CRITICAL / 11 HIGH / 8 MEDIUM / 5 LOW across specs 09, 03, 07; root pattern is missing domain separators + length prefixes; `BroadcastEnvelope` is the only signature with no domain separator.

## Blockers / in-flight

- [#1900 PR-2b WASM engine adoption](pr2b-wasm-engine-adoption-blocker.md) — BLOCKED: no keyless propose/seed on the shared engine; unblock via `TrustedVoteIngest::ingest_proposal`. Items A/B/C/D/H unblocked; E/F/G blocked.

## Reference

- [Key files map](key-files-map.md) — where each construction lives across crates and bindings.

## Standing facts

- Randomness: production uses `OsRng` via `KeyCustody`; tests use `thread_rng()` (also a CSPRNG). No non-crypto RNG on any signing/keygen path found to date.
- Ed25519 verification uses `verify_strict()` on the paths reviewed (BEP44, bridge auth, envelopes).
- DID forms: `did:dht:z<z-base-32>` (prod, canonicality-enforced on decode); `did:key:<hex>` (test-only, non-standard — does not conform to W3C did:key).
