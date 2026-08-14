# Security Reviewer Memory

Index only — one line per entry. Detail lives in the linked topic files.

## Recent reviews (newest first)

- [SCP-RELAYRES-004 FINAL state (9ca2c3f05)](relayres-004-final-9ca2c3f05.md) — both round-1 MEDIUMs CLOSED (`LiveSlot::modify` is module-private beside its only writer). 2 new MEDIUMs: `sanitize_relay_text` misses Unicode bidi/U+2028/U+2029 (`is_control()` is Cc-only); sanitizer applied on the WRITE half only — READ half leaks raw relay text across FFI. No nullifier; DhtMode gate is a real chokepoint.
- [SCP-RELAYRES-004 WRITE path + node live slots (5b89baada)](relayres-004-write-path-5b89baada.md) — all 4 round-1 HIGHs RE-DERIVED closed (signed record is now an output of signing, zero network input; DHT read-back gone). 2 MEDIUMs left: ACK-and-drop suppression undetected; slot `set` is crate-visible not module-private.
- [#2028 F5 Welcome-seam ceiling gate (935d6b929)](issue2028-welcome-ceiling-gate-935d6b929.md) — gate sound + not a nullifier, BUT vacuous after FFI restore (default params), ceiling lowering has no authz effect anywhere, in-actor gate untested.
- [SCP-OUT-031 PR-2a outlet error surface (dccc50c1b + 7eaebb81c)](#) — SECURE. Oracle-collapse holds (NotAuthorized ≡ NotFound byte-identical surface); source_chain always empty on this seam; my round-1 MEDIUM (raw SCP-OUTLET-6080 state leak on unary invoke) fixed by typed `OutletContextNotActive` with const-only Display; ExecutionPanic now hashes outlet_id not panic message.
- [reply-await bounding sweep (1728385f6)](reply-await-sweep-core-1728385f6.md) — SHIP IT. ~61 unbounded oneshots → `bounded_reply_await` (2min); ALL wedge dispositions fail-closed (hard_rate_limit Elapsed→DENY closes a prior bypass; economy→TransportFailed never grants/refunds).
- [SCP-RELAYRES-003 chokepoint closure (370d123d0)](relayres-003-closure-370d123d0.md) — NO FINDINGS. `gate_delete` rate-limits before storage+classify; suppression closed at QUERY via storage-authoritative filter; no nullifier.
- [PR#2235 app-bound/unbound durable event log §8.4](pr2235-app-bound-unbound.md) — no BLOCKER. WARNING: caller-controlled unclamped `timestamp_secs` into the Merkle leaf (backdatable audit log). INFOs: raw provider err in CTX_2057; NotInCeiling-vs-NotInRole cap-enumeration oracle.
- [Event-Log Phase-2 substrate swap (16a2cd42b)](eventlog-phase2-final-16a2cd42b.md) — one HIGH (proposer-backdatable `effective_at`), fixed + re-verified in [4cad781e5](notification-window-backdating-fix-4cad781e5.md) and [f234988bc](notification-window-backdating-fix-f234988bc.md) (observed_at floor, canonical-import re-pin).
- ADR-039 MessageSigner refactor (f7fb2fa6) — ZERO FINDINGS. Key+persona paired in one enum; single fail-closed None check before any mutation; all 3 FFI bridges return typed error, never panic, never unsigned send.
- ADR-039 per-message persona wiring (ba06a8e0 + 7d4cdcf0) — ZERO BLOCKING. Attribution integrity sound (receiver resolves by sender-declared `signing_key_id`, verifies against THAT key). Governance votes pin `#active`. OBSERVATION (pre-existing): `enforce_inner_envelope_category_a` is never called on the live receive path.
- [ADR-051 convergent clock / causal DAG](adr051-convergent-clock.md) — APPROVE + 1 MEDIUM (ADR req#6 machine-readable `anchored` flag exists only as prose in spec07/spec19).
- [PyO3 passphrase storage + redacting Debug (ed6290851)](pyo3-passphrase-storage-ed6290851.md) — CLEAN.
- SDK coverage fail-closed + parity (b27ef7bff, f1edb7498, [f6caeb5dd](trust-error-classifier-f6caeb5dd.md)) — CLEAN. Fuzzy symbol matching removed; error-string classifiers must be START-anchored `startsWith`, never `includes()`; `test-guard.ts` freezes env at module load.
- [PR#76](pr76-findings.md) · [production-readiness commits](production-readiness-commits.md) · [transport expansion SEC-001..008](transport-expansion-audit.md) · [PyO3 PR#112](pyo3-audit-20260228.md) · [persistence layer](persistence-layer-findings.md) · [governance gaps #266](governance-gaps-findings.md) · [tiered storage SCP-213](tiered-storage-scp213.md) · [wiring batch 1 messaging](wiring-batch1-messaging-findings.md) · [black-hat PR#4](/tmp/black-hat-review.md).

## Cross-cutting patterns (the durable value)

- Clock: `unwrap_or_default()` / static-fallback on `SystemTime` is a systemic recurring pattern; `now_secs()` returning 0 on clock error is fail-open.
- Freshness validators must check BOTH directions (past staleness AND future skew); `saturating_sub` silently accepts future timestamps.
- Hash/HKDF inputs with variable-length fields need length prefixes or domain separators — boundary-shift collisions found in `build_hpke_info` (access keys) and Merkle event names.
- Signed wire types need `deny_unknown_fields` (sender-key, access-key, BlockListEvent still missing).
- Nonce/replay: sender keys have `NonceDedup`, access keys still do not; `handle_sender_key_request` has no timestamp/nonce check.
- Unbounded collections are the most common MEDIUM: SenderVelocityTracker, recv_sequence_tracker, EventLogMetrics, broadcast subscribers/authors/block_list, CheckpointManager::checkpoints, participation_cache, standing_contexts, static DashMap registries (no eviction).
- Empty-collection-wrapped-in-`Some` vs `None` is a recurring FFI-bridge fail-open/fail-closed bug (UCAN ceiling #339). Convert empty → None at the boundary.
- WASM/NAPI reimplementations of scp-core validators consistently drop defensive checks — always diff line-by-line against core.
- Error-string classifiers and revocation checks must use exact/anchored matching, never `contains()` (CapabilitySuspension `contains("write")`, RemoveSigner token revocation).
- Multiple mutexes on one struct need a documented acquisition order (crypto.rs broadcast_keys vs sender_keys deadlock).
- Load-modify-store on shared storage (`append_block_list_event`) needs atomicity or caller-side serialization.
- TOCTOU: a capability checked under one lock acquisition and acted on under another is a TOCTOU (GovernancePropose fixed, GovernanceVote known gap). Phase-3 lock reacquire must verify a generation token.
- zeroize is inconsistent: store layer yes; identity signing keys, MLS key pairs, TLS private keys no. `destroy_group` FREES but does not zeroize the Ed25519 signer.
- `bridge_instance()` enforces lifecycle; `context_manager()` does not — all bridges must route through `bridge_instance()`.
- clippy denies unwrap/expect in lib code; Rust 2024; `#![forbid(unsafe_code)]` except scp-ffi.

## Known-open findings by area

- **Ceiling / governance**: `ModifyCeiling` never propagates to other nodes (NoMlsChange, no receive arm, `CeilingModified` leaf has zero consumers); FFI `ceiling_strings` is genesis-only forever; `apply_pending_ceiling_modification` takes a caller-supplied timestamp (§5.3.2 window is caller-controlled). `validate_projection_ucan` is structural-only. `compute_vote_hash` omits proposal_id (cross-proposal replay). `verify_vote()` defined but never called. Conflict pair RestoreReadAccess-vs-RestoreReadAccess missing.
- **UCAN**: `validate_ucan_stateless` skips nonce/revocation/chain/attenuation. AND-composition `check_and_composition` allows None/None/free = Ok. `system_assign_role` is `pub` and bypasses RoleAssign audit differentiation.
- **Crypto/custody**: SqliteKeyCustody still derives the pseudonym HMAC key from the PUBLIC key (oracle) — InMemory/File were fixed to HKDF(private); WASM custody JSDoc still documents the insecure pattern. HKDF `info` is empty (no forward separation).
- **Event log / WASM**: `compute_event_hash` in WASM ≠ native (`SHA-256(0x00||type||ctx||ts)` vs MessagePack of the full event) — Merkle roots never match cross-platform; conformance tests only check tree shape.
- **FFI/bridges**: `did:key:<hex>` non-standard form not `cfg(test)`-gated (UniFFI/NAPI/WASM); NAPI `ucan_mint` zero-signature placeholder; `transport_connect` accepts any URL scheme; scp-platform `testing` feature in production deps; single-context `restore_context` passes `ContextParams::default()` and the next persist writes it durably over genesis.
- **Providers**: `encrypt_message` skips the ADR-007 sender-key layer; `init_broadcast_key` stores the wrong key material; `validate_key_package` only checks the `did:` prefix.
- **Node/relay**: dev_token logged at INFO and minted with `thread_rng()`; no localhost enforcement; bridge secret in query param; total-connection-limit TOCTOU. MCP: no pre-initialization guard, `resources/read` skips UCAN.
- **Bridge/shadow identity**: GovernanceAction carries no signature; canonical hash has no field separators.
- **Docs-only guarantees** (enforce or delete): BootstrapConfig `expected_creator_did` is documentation-only; `scp-ffi/CLAUDE.md` requires `sync_role_state_from_manager` after ModifyCeiling and no bridge does it.

## Positive patterns worth preserving

- Reject-before-mutate gates placed ahead of every mutation, sharing ONE predicate between the front door and the chokepoint.
- Fail-closed defaults: economy, `from_class` unregistered slug → Authorization, `SigningKeyId::from_fragment` (single canonical decoder), production key resolvers returning None for all kids.
- Oracle collapse: not-authorized and not-found produce byte-identical surfaces; decrypt collapses CiphertextTooShort into AuthenticationFailed.
- Type-enforced persistence classes (`ClassSCell` with no `DerefMut`) instead of source-text scanners.
- Signature verified BEFORE anti-replay; membership BEFORE signature BEFORE Merkle root on checkpoints.
- Zeroize + redacting `Debug` on AccessKey / IdentityEntry / CertificateData / the three PyO3 bridges.
- Exhaustive match arms in governance dispatch (no wildcards); `OpenResult` enum forcing exhaustive handling.
- Escrow/budget pattern with `reverse_spend`; `ConsequenceRule::validate` whitelist.

## Gotchas for future sessions

- `cd /Users/alec/Developer/limn/scp` is the MAIN worktree and is frequently STALE/detached. Read the branch worktree path, or use `git show <sha>:<file>`.
- The shared cargo target dir is poisoned by the stale main checkout — set an isolated `CARGO_TARGET_DIR` before running cargo in a worktree.
- Never modify the enforcement files listed in root CLAUDE.md to make a check pass.
