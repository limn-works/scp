---
name: adr057-t2-client-storage-d4c96f87e
description: ADR-057 T2 scp-client storage wiring review @ d4c96f87e — 1 HIGH (spec§17.5 contradicts code+tests) + 2 MOD
metadata:
  type: project
---

# ADR-057 T2 — Client storage wiring @ `d4c96f87e` (base c102f8222, 2026-07-03) — NEEDS DISCUSSION

Branch feat/adr057-t2-client-storage; HEAD d4c96f87e atop e31c063a6 (scp-mls snapshot primitives) on c102f8222. Range = 2 commits, 19 files, +2217/-84. Nested worktree path `.claude/worktrees/adr057-t1c/.claude/worktrees/adr057-t2`.

**What's SOLID (code layer 0-findings):** Real wired read path — `ScpClient::new(signer, storage: Arc<dyn Storage>, clock)` is the SINGLE canonical constructor, no fresh-vs-restore boolean (agent-first ✓), storage REQUIRED param no silent default (caller picks ✓). `restore_from_storage` enumerates by key-prefix (`scp-client/ctx/`, `scp-client/pending/`), reconstructs+verifies ALL into staging vecs, installs atomically — single corrupt/foreign snapshot fails whole construction closed. `ContextSnapshot` (snapshot.rs) captures MLS state + §9.16 sender-key state + event stream + membership + §9.9.3 checkpoint; restore recomputes event-log root and compares (fail-closed on mismatch), owner_did binding checked, format-version gate, Drop zeroizes key material. Storage trait is flat 4-method sync KV (get/put/delete/list_keys), all fallible, `get`→Ok(None) only for genuine absence. wasm JsStorageAdapter forwards to injected JsStorage extern; actual IndexedDB impl deferred to TS SDK Slice-3 (sync-facade-over-mirror contract) = accurate. Tests (snapshot_restore.rs, 521 lines) pin fail-closed construction, exactly-once buffered delivery, pending-join-resume.

## FINDING 1 (HIGH) — spec §17.5 edit contradicts the code + tests it governs (phantom provenance, same change set)
`.docs/specs/17-persistence-and-storage.md:541` (new): "The receive buffer ... and pre-join key-package material are intentionally **not** persisted — they are transient and re-established on return, keeping decrypted plaintext out of storage." And :545: "A decrypted-but-undrained application message lost on a crash-before-consumption is not recoverable ... accepted ADR-057 lose-local-state property."
BUT the code persists BOTH:
- Receive buffer: `snapshot.rs` field `buffered_messages` + whole module-doc section "# The receive buffer IS persisted (and why)"; test `restore_resumes_a_converged_context_from_storage` asserts the undrained message survives restore and is "delivered exactly once."
- Pre-join material: `client.rs` `generate_key_package_for_join` persists `scp-client/pending/{id}` blob BEFORE returning KP; restore restores it; test `pending_join_completes_after_restore` — "reopened tab restores the pending material and joins with it."
So the spec's persistence-model AND its security rationale ("keeping decrypted plaintext out of storage") AND its lose-local-state claim are all false vs the implementation. Code path is deliberate/test-pinned → likely resolution = FIX THE SPEC to match (persist buffer, rely on AEAD-at-rest; persist pending blob for crash-safe joins). Must reconcile before shipping; §17.5 as written is phantom provenance.

## FINDING 2 (MODERATE) — in-memory storage labeled "development/test backend" (contradicts ADR T2 bullet + Alec's explicit mandate "not dev-only")
ADR-057 T2 bullet: "in-memory and IndexedDB both valid production backends." Mandate: docs must NOT call in-memory dev/test-only. 4 sites do: `scp-client/src/storage.rs:13`, `:68` ("development/test storage backend"), `snapshot.rs:11` ("in-memory in dev"), `lib.rs:41` ("[MemoryStorage] in dev"). NB distinct from prior [feedback_in_memory_storage_is_dev_only] which is about the scp-runtime InMemoryStorage system-of-record — the ADR-057 CLIENT Storage explicitly blesses in-memory as prod. (signer.rs:41 labels LocalSigner "development/test identity backend" — defensible per ADR custody-signing-is-a-later-slice; OBS not finding.)

## FINDING 3 (MODERATE) — ADR-057 T2 bullet has no landed-status marker (T1/T1c-a precedent)
ADR file NOT in the diff. T1 bullet reads "(landed in this change set)"; T1c-a got a landed marker per prior review. T2 bullet (line 87) still future-tense: "**T2 — Client storage wiring.** Make ... close the unwired-read-path gap." This change set implements T2 but the governing ADR still reads unlanded. Add the landed marker per precedent.

GOTCHA: nested worktree path is real (adr057-t1c/.claude/worktrees/adr057-t2). Spec §17.5 lines 537-545.
