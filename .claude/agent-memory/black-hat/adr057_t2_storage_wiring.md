---
name: adr057-t2-storage-wiring
description: ADR-057 T2 client snapshot/restore storage wiring review @d4c96f87e — spec/code contradiction (HIGH), pending-blob owner-binding gap (MED), honest rollback docs (PASS)
metadata:
  type: project
---

# ADR-057 T2 client storage wiring — black-hat review @d4c96f87e (base c102f8222)

Branch feat/adr057-t2-client-storage. MLS snapshot primitives (scp-mls/src/snapshot.rs) +
per-context ContextSnapshot (scp-client/src/snapshot.rs) + per-op persist + fail-closed
constructor restore (scp-client/src/client.rs) + wasm JsStorage adapter.

## Trust model (as stated, honest)
Storage backend = the tab-custody/plaintext boundary. Malicious backend/XSS'd origin is
SAME trust domain as the tab (already has plaintext, can call any API). So: crafted-MLS-blob,
resurrect-closed-ctx (backend ignores delete), rollback = all WITHIN trust domain, not
escalations. Sole real defense = backend provides AUTHENTICATED encryption at rest. Docs say
this EXPLICITLY (snapshot.rs:19-31,59-68; error.rs:66-68; spec §17 "Authenticated encryption
at rest" bullet). owner_did check = accidental-cross-identity guard, NOT a boundary vs
malicious backend (attacker controls blob, can set owner_did=victim).

## Findings
1. HIGH (phantom provenance): spec .docs/specs/17-persistence-and-storage.md:541 (added THIS
   PR) says receive buffer + pre-join key-package material are "intentionally NOT persisted...
   keeping decrypted plaintext out of storage." CODE PERSISTS BOTH: buffered_messages in
   ContextSnapshot (snapshot.rs:34-47,137) + separate scp-client/pending/{id} blob
   (client.rs:273-285, test pending_join_completes_after_restore). Spec self-contradicts its
   own PR's code + security rationale. Code design is CORRECT (buffer persist required for
   exactly-once since ratchet advanced+persisted; pending persist required to resume join).
   Fix = correct the SPEC to match as-built.
2. MEDIUM (defense-in-depth parity): PendingJoinSnapshot (scp-mls snapshot.rs:208) carries NO
   owner_did/context binding; restore_pending_join (snapshot.rs:296) adopts any pending blob
   verbatim. ContextSnapshot enforces owner_did (snapshot.rs:290) + embedded-ctxid==key
   (client.rs:855). Asymmetric: a benign backend bug (or malicious plant) serving identity A's
   pending blob to B's client is silently accepted → B could join a group under A's MLS leaf
   credential (SCP-layer did=B, MLS-layer cred=A mismatch). Bounded (needs matching Welcome;
   within trust domain) but the guard parity is missing. Recommend: bind owner did into
   PendingJoinSnapshot, verify on restore.
3. LOW (doc-correctness): scp-client/src/storage.rs:10-13 module doc names
   ScpClient::restore_context / restore_all_contexts — NEITHER EXISTS (restore is via new()
   only). Broken intra-doc links (no broken_intra_doc_links deny found, so no CI break) +
   misdescribes API.
4. LOW/INFO (unbounded restore): no size/count bound on blob, events replayed, or rmp nesting
   (client.rs:844/876 Vec::with_capacity from attacker-controlled list_keys().len()). Self-DoS
   within tab trust domain; acceptable under model but note for a future less-trusted backend.

## What RESISTS attack (verified sound)
- Rollback (older-but-valid snapshot → lowered recv_sequence_tracker + sender_key_epochs floor
  → replay-window regression / double-accept): UNDEFENDED BY DESIGN and docs say so explicitly
  (snapshot.rs:26-31,59-68). MLS forward-secrecy means rollback does NOT decrypt NEWER traffic
  (needs the commit) — harm is replay-floor regression, exactly as documented. On client there
  is NO live-store max-merge (native path has it); tab reopen has no prior state so snapshot is
  verbatim — inherent, honestly documented. NOT oversold.
- MlsGroup::load on attacker-controlled provider entries: trusts storage (no re-verify), but
  within trust boundary; returns Result, no panic (from_parts/signer_key_pair/group_id all
  ?-guarded, group.rs:140-206). rmp_serde safe-deserialize.
- Crash window (b): put immediately after mutation; only cheap in-memory append_log_event +
  push_event between decrypt and put (client.rs:527-597). Lost-decrypt-on-crash re-decrypts on
  restore = correct (msg never delivered), not double-delivery. Minimal + documented.
- Fail-closed matrix well-tested (tests/snapshot_restore.rs): corrupt/truncated/owner-mismatch/
  backend-err/vanished-key/1-of-2-corrupt-atomic/failing-put-no-ciphertext/close-deletes-FS.
  Corrupt test tampers right prefix (scp-client/ctx/). Checkpoint-mismatch pinned at unit level
  (snapshot.rs checkpoint_mismatch_fails_closed).
- Zeroization thorough (Drop + explicit, all key-bearing fields). wasm unsafe Send/Sync
  honestly scoped w/ embedder obligation (storage.rs:30-56). Debug redaction everywhere.
- Cross-context blob swap caught by embedded-ctxid==key (client.rs:855) — but NOT unit-tested
  (minor coverage gap, guard is present).
