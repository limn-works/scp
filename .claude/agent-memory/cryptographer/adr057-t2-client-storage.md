---
name: adr057-t2-client-storage
description: ADR-057 T2 scp-mls/scp-client snapshot-restore storage crypto review (branch feat/adr057-t2-client-storage @d4c96f87e) — SOUND, one LOW error-path zeroization gap
metadata:
  type: project
---

# ADR-057 T2 — client snapshot/restore storage (@d4c96f87e, base c102f8222)

Reviewed crates/scp-mls/src/snapshot.rs (MlsGroupSnapshot, PendingJoinSnapshot) + crates/scp-client/src/snapshot.rs (ContextSnapshot) + client.rs driver. Verdict: **SOUND**. Modeled faithfully on scp-runtime/src/crypto/mls/provider.rs export/restore_crypto_state (byte-identical mechanics minus runtime-only X25519 wrapping keypair, which scp-mls has NONE of — InMemoryMlsProvider = openmls_rust_crypto::OpenMlsRustCrypto, ALL secret state lives in MemoryStorage.values; client uses create_group wrapping_pubkey=None, sender keys exchanged out-of-band raw bytes → serialize_state dump of storage().values + signer_bytes + group_id is COMPLETE).

**Key facts:**
- MLS signer serialized = openmls SignatureKeyPair (FRESH MLS leaf key, group.rs:316/672 `SignatureKeyPair::new`), NOT the DID long-term identity key (that lives in injected Arc<dyn Signer>, never snapshotted). Distinction honest.
- Restore ordering: sender_key_epochs (restore_epoch_high_water) BEFORE keys (set_unchecked); the two are independent HashMaps (epochs vs keys) so order is truly immaterial. #1608 monotonicity uses set_checked which client never calls for peers.
- recv_sequence_tracker (the ACTUAL client replay floor — client never advances peer sender_key_epochs via set_checked, only records tracker) round-trips → replay/reorder rejection preserved across restart. sender_key_epoch (local monotonic) round-trips.
- receive_message persists on EVERY Ok incl. commit-merge Ok(false) + proposal Ok(false); ONLY UnsupportedMembershipChange returns Err pre-persist (scp-mls rejected pre-merge, no state changed). Exactly-once across crash holds (crash-before-put loses+redoes decrypt from durable pre-decrypt state = safe; crash-after-put → FS/tracker rejects re-delivery). Pinned by snapshot_restore.rs restore_resumes_* (pre-restore ciphertext replay rejected after restore).
- close_context deletes BOTH durable blobs FIRST then destroys in-memory group (FS ordering: delete-fail → live+retryable, never resurrectable). Pinned by close_deletes_durable_state_forward_secrecy.
- event_log_root compare = torn-write/corruption/truncation guard on event log ONLY; root in-blob so NOT tamper-resistant; whole-blob authenticity + anti-replay-floor integrity rests on backend AUTHENTICATED encryption at rest (§17.5). Doc is EXPLICIT and honest, no overclaim.
- ClientError variants carry only ids/DIDs/epochs/messages, no key bytes. ContextSnapshot/Inbound/MlsGroupSnapshot/PendingJoinSnapshot all redacting Debug, no Clone.

**LOW finding (only one):** MlsGroupSnapshot + PendingJoinSnapshot have NO `impl Drop` — rely on explicit zeroize_secrets() at end of serialize/deserialize. Early-`?`-return error paths leak un-zeroized secrets: deserialize_state signer-deserialize-fail (snapshot.rs:166) leaves signer_bytes un-zeroized (zeroize at :168 is AFTER); RwLock-poison paths leak full entries+signer. INHERITED from native MlsCryptoSnapshot (also no Drop). BUT same PR's ContextSnapshot DID add `impl Drop` (:437) for exactly "any path incl error" — internal inconsistency. Fix: add Drop→zeroize_secrets to both scp-mls structs (+backport native). Mitigated: RwLock-poison unreachable in single-thread wasm; signer-fail path narrow (inner blob must parse as struct but signer_bytes not a valid keypair). Not blocking.
