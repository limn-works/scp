# #1909 Phase 2 — WASM↔native sender-layer interop (commit c6856bc9b)

VERDICT: GO. WASM↔native sender-layer interop holds, in-session protections intact, BLACK-1909-01 removal is crypto-sound.

## THE FIX (BLACK-1909-01): removed cross-party portable replay-state persistence
- DELETED: WasmReplayStateSnapshot struct, replay_state_snapshot()/restore_replay_state() (state.rs), pending_replay_state field + ContextExport replay_state field + import seeding (manager.rs). Zero remaining refs in crates/scp-ffi/wasm/src/ (grep clean).
- WASM_EXPORT_VERSION 6 -> 5 (reverted the v6 that added replay_state to signed snapshot).
- WHY SOUND: the deleted machinery used SenderKeyStore::restore_epoch_high_water (NON-monotonic install) to seed a THIRD-PARTY sender's epoch high-water from an importable, creator-signed snapshot. A signed-but-malicious creator could set any sender's high-water arbitrarily high → inflate the receive ceiling (open: epoch > stored_high_water + MAX_EPOCH_ADVANCE) → BYPASS MAX_EPOCH_ADVANCE. Also could reopen replay by lowering recv tracker. Removal excises this seed.

## §9.16.1 interpretation is CORRECT
- Native has TWO crypto-state surfaces:
  1. MlsCryptoSnapshot (provider.rs:105) — LOCAL persistence/restore (restore_crypto_state @2055). DOES carry recv_sequence_tracker + restore_epoch_high_water. Restored ONLY into the same node. This is what §9.16.1 "persist the tracker in the crypto state snapshot" refers to.
  2. Portable cross-party export (context/export_import.rs) — emits `mls_crypto_state: Vec::new()` (lines 763/989, broadcast_helpers 776/842). Carries NO replay/freshness cache. A native node importing a FOREIGN portable export gets a FRESH receive window.
- WASM structurally lacks surface #1 (ADR-034: no serialized live MLS; re-establish via fresh Welcome). So fresh empty window IS the correct WASM behavior — it matches native's FOREIGN-NODE import, not native's local restore. Prior WASM code wrongly fused the local-persist MUST onto the portable export.

## In-session protections PRESERVED (WasmCryptoState::decrypt_message, state.rs ~198-251)
- Logic is byte-equivalent to native open (provider.rs 1730-1753):
  parse_sender_header -> ceiling (epoch > store.epoch(ctx,sender)+MAX_EPOCH_ADVANCE) BEFORE recording tracker -> replay/reorder (epoch<last || (epoch==last && seq<=last_seq)) -> record (epoch,seq).
- High-water now ONLY advanced LIVE (process_incoming_sender_key / set_checked), never from importable snapshot.
- governance_rotate_sender_key advances sender_key_epoch (saturating_add 1), clears recv tracker (rotation = new key context).

## Epoch source = sender_key_epoch (§9.16.5), NOT MLS group epoch
- Native seal binds state.sender_key_epoch into BOTH AAD (provider.rs:1594) and header (:1600). open reconstructs AAD from PARSED header epoch.
- WASM encrypt_message uses self.sender_key_epoch for both (state.rs:148/152/164). Matches.
- Spec §9.16.5: epoch starts at 1 (was 0). Native seeds sender_key_epoch:1 (provider.rs:758). WASM INITIAL_SENDER_KEY_EPOCH=1. Rationale: epoch≥1 BE first 4 bytes never collide with MANAGEMENT_MSG_MAGIC=[0x53,0x43,0x50,0x4D] ("SCPM"). (Note: epoch>=1 BE byte0=0x00 for epoch<2^56, ≠0x53 — argument holds; even epoch=0 would be safe but ≥1 is the stated guarantee.)

## Strengthened conformance test = GENUINE cross-family oracle
- cross_family_sender_layer_header_and_aad_converge (wasm_conformance.rs): drives REAL MlsCryptoProvider seal->open. Bob joins via Welcome (MLS epoch->1). Alice rotate_sender_key (sender_key_epoch 1->2, NO MLS commit) → divergence sender_key_epoch=2 ≠ MLS epoch=1. Asserts Bob's export_sender_key_epochs(alice)=2 (proves epoch axis is sender-key epoch). seal at rotated epoch, open succeeds. Tampered-header (rotated_epoch+1) → AEAD fail-closed.
- Regression detection genuine: header-only MLS-epoch regression → AAD(seal=2) vs AAD(open=parsed-header=1) mismatch → AEAD fails closed. Both-axes regression → caught by export_sender_key_epochs=2 assertion + tampered-header guard. Divergence makes tautological pass impossible.
- WASM companion rotate_advances_epoch_in_header_and_aad (state.rs:582) drives real WasmCryptoState rotation, asserts tracker records (2,0) = rotated epoch from header. Pins WASM wrapper. ADR-034 forbids scp-runtime depending on scp-ffi-wasm, so two tests pin the two wrappers over the same property.
- VERIFIED: cargo test -p scp-runtime --features testing ... cross_family_... = ok (1 passed).

## No crypto regression from removal. Wire convergence holds (header epoch||seq BE, AAD raw context_id string + sender_did + sender_key_epoch + sequence, byte-identical native↔WASM).
