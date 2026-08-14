# Saga Phase 2D + broadcast hosting-handshake types (commits b001f49a6, a784ca50d) — MOSTLY CLEAN, 1 gate-quality gap

Branch saga-2c-bh @ a784ca50d. Reviewed two commits.

## Part 1: broadcast hosting_handshake.rs (b001f49a6) — DEFENSES HOLD
File: crates/scp-protocol/src/context/broadcast/hosting_handshake.rs
11 compiled adversarial probes (bh_hosting_handshake_probes.rs, since deleted) ALL passed:
- Cross-protocol confusion: request sig spliced onto grant (and reverse) REJECTED — distinct domain separators SCP-BCAST-HOST-REQ-V1: / SCP-BCAST-HOST-GRANT-V1: are the SHA-256 leading prefix.
- Splice/length-prefix: subscriber_did (VarBytes len-prefixed) / wrapping_pubkey (Fixed32) boundary unambiguous; slid-byte produces distinct preimage.
- Ed25519 malleability (S+L): verify_strict REJECTS non-canonical S.
- JCS: verify() RE-canonicalizes typed struct via to_jcs() — never trusts wire JCS bytes; wire whitespace harmless, value change breaks.
- clamp/validate: clamp leaves expires_at_ms==0 in place (documented) BUT sign() calls validate() → cannot sign a perpetual grant. Range fields clamped not rejected.
- gated/ungated: OptVarBytes absent=SHA-256(0x00) sentinel ≠ present zero-length VarBytes(0x00000000). ungated sig can't be lifted to gated body and vice-versa (downgrade blocked).
- request/grant preimage never collide (brute 256 epochs).
- serde fixed-len deserializers (serde_pubkey_32 etc.) reject wrong-length wire input.
- no self-referential key trust: verify() takes externally-resolved VerifyingKey; attacker-signed request claiming victim DID fails vs victim's resolved key.
canonical.rs (§9.5.1) is sound: domain=leading raw prefix, VarBytes 4-byte BE len-prefix, fixed fields fixed-width, Absent=32-byte sentinel. Fixed schema per struct = no arity ambiguity.

## Part 2: Phase 2D restore_on_startup (a784ca50d)
supervisor.rs:7873 restore_on_startup = replay_unresolved_sagas().await? THEN restore_all_contexts().await.
Routing ENFORCED at all 4 persistence bridges (pyo3/napi/uniffi + shared BridgeInstanceCore::restore_all_persisted_contexts) → restore_on_startup. WASM unchanged (no journal, ADR-034). Only direct Supervisor::restore_all_contexts() callers: inside restore_on_startup, WASM's own manager, and tests. Clean.
replay only processes load_unresolved() entries = `!entry.state.is_terminal()` filter (saga_journal.rs:518) + max-seq-per-saga. So a SETTLED saga CANNOT be re-driven; double-apply structurally prevented. Journal is internal durable state (local Storage), not attacker wire data — crafted entry is out-of-threat-model unless storage itself compromised (decode_entry validates structure).

## FINDING (LOW, gate-quality): pipeline_wiring ordering assertion is comment-evadable
`restore_on_startup_runs_replay_before_restore` (pipeline_wiring.rs:~460) uses extract_fn_body() (INCLUDES comments) then body.find("replay_unresolved_sagas()") < body.find("restore_all_contexts()").
PROVEN evasion: reorder the real calls (restore first, replay second) BUT add a comment naming `replay_unresolved_sagas()` ABOVE them → find() matches the comment-token first → assertion PASSES on reordered code. Mutation confirmed: gate green while code wrong.
The 3 honest mutations (reorder w/o comment, drop-replay, bridge-bare-restore) ALL correctly caught.
WORSE: the runtime test restore_on_startup_replays_unresolved_journal_without_manual_replay only proves replay RUNS, not that it runs BEFORE a SUCCESSFUL restore — its restore leg always errors PersistenceFailed (NoopPersistence) before making any caller resident, so it passes against the reorder mutation too. So §17.16.4's actual ordering invariant (replay must observe non-resident caller before restore makes it resident) rests SOLELY on the comment-evadable substring gate; no behavioral test proves it.
Fix options: strip comments before find() in extract_fn_body for ordering checks; OR add a runtime test where restore SUCCEEDS and makes a caller resident, asserting replay's ReversalOutstanding path fired first. Insider-adversary severity (gate is defense-in-depth per CLAUDE.md, not primary), but the ordering property has no sound test.
