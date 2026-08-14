---
name: adr057-t2-client-storage
description: ADR-057 T2 prod-ready snapshot/restore storage wiring for scp-client — review @d4c96f87e, INCOMPLETE(narrow), 2 non-code divergences
metadata:
  type: project
---

ADR-057 T2 client-storage wiring review. Branch feat/adr057-t2-client-storage @d4c96f87e (atop e31c063a6 scp-mls snapshot primitives), base c102f8222. Nested worktree .claude/worktrees/adr057-t1c/.claude/worktrees/adr057-t2. READ-ONLY.

**Verdict: INCOMPLETE (narrow) — code 100% complete, 2 non-code-behavior divergences.**

All 12 plan items DONE + code-quality sub-checks (a,c,d,f) DONE:
- Sync `Storage` trait (scp-client OWN trait, NOT scp-platform's async 6-method one): fallible get(Option)+put+delete+list_keys.
- Prefix keys `scp-client/ctx/{id}` + `scp-client/pending/{id}`, no manifest (restore enumerates by prefix).
- Snapshot on EVERY mutating op verified at call sites: create/add_member/join/send/install_sender_key/drain(non-empty)/receive(every Ok) → persist_context; generate_kp → persist pending blob; close → deletes both blobs FIRST (forward-secrecy ordering). Remove-bearing Commit returns Err BEFORE write (scp-mls drops StagedCommit pre-merge, state stays consistent).
- `ScpClient::new -> Result` single canonical ctor calls restore_from_storage: version envelope u16, context-id-vs-key match + owner_did verify (in restore), MLS rebuild, #1608 epoch-floor ordering (restore_epoch_high_water FIRST then set_unchecked keys), event replay via append_unsigned_event + root() compare, all-or-nothing STAGING then commit.
- Full state inventory: local_sender_key+epoch, sender_key_entries, sender_key_epochs(floors), recv_sequence_tracker, events, buffered_messages(event_buffer, MessageReceived-only else fail-closed), members, member_sequence_numbers, event_log_root. pending_joins persisted SEPARATELY.
- scp-mls/src/snapshot.rs: MlsGroupSnapshot + PendingJoinSnapshot, serialize_state/deserialize_state + serialize/restore_pending_join, zeroize on Drop + after use, manual redacting Debug, no Clone. Exported from lib.rs. MlsError::Snapshot added.
- wasm: listKeys extern added, get now fallible (Result, no more swallow-as-absent), from_parts + from_js now Result, STORAGE 8001-8003 mapping + test, sync-facade embedder-contract docs.
- Error taxonomy: StorageBackend(8001)/StorageCorrupt(8002)/StorageIdentityMismatch(8003).
- §17.5 spec updated: "Browser Clients Are Remote Thin Clients" → "Browser Clients Run Storage In-Process" (coherent w/ final design; crash-consistency + AEAD-at-rest mandatory).
- Tests: snapshot_restore.rs full fail-closed matrix (corrupt/truncated/owner-mismatch/failing-read/vanishing-key/one-of-two-atomicity/failing-put-no-ciphertext/close-forward-secrecy); scp-mls 5 unit tests; wasm restore_through_wasm_surface + map-backed round-trip + code-mapping test.
- Runtime UNTOUCHED (item 11 skip). Fence intact: scp-client deps = scp-clock/did/protocol/event-log/mls + openmls/tls_codec/serde/rmp-serde/zeroize/thiserror only; zero scp-runtime/identity/platform/tokio.
- (a) `#[allow(dead_code)]` on storage field GONE (only unrelated custody.rs:114 test-scaffold allow remains). (f) No new publishable crate (root Cargo.toml + workspace members untouched, no new [[package]]); release.yml correctly untouched (scp-client/scp-mls already publishable).

**FINDING 1 (MEDIUM, artifact divergence):** ADR-057 line 83 header ("T1 is executed by this change set; **T1c and T2 follow**") + line 87 T2 bullet (imperative "Make scp-client's Storage a real…wired dependency…close the unwired-read-path gap") still frame T2 as FUTURE/unlanded — but this branch LANDS + enforces it (spec §17 flipped to describe it as current design). Branch did NOT touch the ADR. Per the T1 precedent (bullet marked "(landed in this change set)"), T2 bullet needs a landed-status update. Phantom provenance: ADR describes shipped work as to-do. Same class as ADR-049 2J lesson (STATUS must move, not just prose). NOTE: T1c bullet ALSO lacks a landed marker despite T1c-a having landed — so the "landed-marker" discipline is inconsistently applied in this ADR generally.

**FINDING 2 (LOW, Cargo.lock inconsistency):** fuzz/Cargo.lock `scp-mls` package entry omits the new UNCONDITIONAL `zeroize` dep this branch added to scp-mls/Cargo.toml [dependencies] (root Cargo.lock has it). fuzz builds scp-mls transitively via scp-runtime. Self-heals in ci.yml:830 (`cargo +nightly check --manifest-path fuzz/Cargo.toml`, NO --locked) so not CI-breaking, but committed fuzz lock is stale → item (e) "both Cargo.locks consistent" NOT satisfied. Recurring fuzz-lock finding (also hit in ADR-057 T1c review).

**OBSERVATION (item 11 skip-note):** approved skip of scp-runtime consolidation (byte-incompat w/ committed KATs) is NOT documented in any committed artifact. Runtime correctly untouched. scp-mls snapshot module doc says mechanics "mirror the proven native-runtime export_crypto_state/restore_crypto_state path" but doesn't state runtime is deliberately NOT unified onto the new helper nor why. Minor doc gap, non-blocking.

LESSON: on ADR-057 phased slices (T1/T1c/T2) the landed-status markers are applied inconsistently — always diff the ADR slice bullet's STATUS against what the branch actually ships; a slice that lands work but leaves its own bullet imperative/future = divergence. Also re-confirm the recurring fuzz/Cargo.lock stale-edge whenever a crate in fuzz's transitive graph (scp-mls/scp-runtime/etc.) gains an unconditional dep.
