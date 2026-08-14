---
name: adr057-t2-client-storage-d4c96f87e
description: ADR-057 T2 scp-client Storage trait + snapshot/restore + wasm JsStorage review @d4c96f87e (branch feat/adr057-t2-client-storage)
metadata:
  type: project
---

ADR-057 T2 "prod-ready snapshot/restore storage wiring" review, range c102f8222..d4c96f87e
(base e31c063a6 = scp-mls snapshot primitives; HEAD d4c96f87e = scp-client wiring).

Verdict: NEEDS REVISION — 1 MODERATE doc contradiction + 1 MODERATE missing query + 1 LOW.

**Why:** Reviewed the new participant-driver persistence surface (browser-in-tab, keys on-device,
IndexedDB/OPFS out-of-band snapshots). ADR-055 remote-thin-client is SUPERSEDED by ADR-057
in-process storage.

**How to apply (findings to re-check on next round):**
- MOD-1 (doc/alignment): spec §17.5 (17-persistence-and-storage.md, amended IN THIS SAME PR) says
  the receive buffer + pre-join key-package material are "intentionally NOT persisted … keeping
  decrypted plaintext out of storage." Code does the OPPOSITE and documents why: snapshot.rs persists
  `buffered_messages` (FS ratchet already advanced → unrecoverable via relay) AND a separate
  `scp-client/pending/{id}` blob for pending-join material. Spec is the stale/wrong artifact; fix spec
  down-flow (artifact-flow invariant). An SDK author reading §17.5 builds a wrong mental model of the
  blob contents + at-rest boundary.
- MOD-2 (discoverability/ergonomics): NO context-enumeration query. `ScpClient::new` restores N
  contexts but every accessor (member_dids/event_log_root/mls_epoch/send/receive) REQUIRES a known
  context_id. After a tab reopens the embedder cannot list what restored — must keep a parallel id
  list in its own storage, defeating the "no separate manifest" / "reconstructs its live state"
  value prop. Key prefixes (CTX_KEY_PREFIX/PENDING_KEY_PREFIX) are private, so it can't listKeys them
  cleanly either. Add `context_ids() -> Vec<String>` on ScpClient + `contextIds` on WasmScpClient.
  Paints Slice-3 TS SDK into same corner.
- LOW (minimality): scp-mls exports `MlsGroupSnapshot` + `PendingJoinSnapshot` (lib.rs:63) but both
  have all-private fields, no public ctor/accessor, and appear in NO public signature (serialize_state
  →Vec<u8>, deserialize_state→ScpMlsGroup; serialize_pending_join→Vec<u8>, restore→(provider,signer)).
  Dead public surface — should be unexported/pub(crate).

**Strengths (don't re-flag):** Storage `get -> Result<Option<Vec<u8>>, String>` makes absence
(Ok(None)) vs backend-fault (Err) impossible to conflate — doc'd at trait + enforced in JsStorage
extern (undefined→None, throw→8001). String error is the RIGHT call for LLM backend authorability
(no SCP taxonomy to learn; driver classifies into 8001/8002/8003). Empty-store=fresh doc'd plainly on
new(). ClientError StorageBackend/StorageCorrupt/StorageIdentityMismatch names self-evident, each
doc'd w/ trigger + 8001/8002/8003. MLS snapshots opaque, can't restore-into-wrong-group (deserialize
mints fresh group from embedded group_id), no new openmls leak (provider/SignatureKeyPair already in
generate_key_package sig). wasm camelCase consistent. JsStorage sync-facade-over-mirror contract is
thorough. persist-before-return crash ordering + owner-DID binding + §9.9.3 checkpoint sound.
