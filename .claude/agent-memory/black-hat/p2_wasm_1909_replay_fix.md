# BLACK-1909-01 WASM replay-state fix (commit c6856bc9b)

## Status: CLOSED in code. One spec-provenance gap remains (BLACK-1909-S1).

### The fix (verified GO)
- WASM dropped ALL portable replay-state persistence: removed `WasmReplayStateSnapshot`
  type, `replay_state` snapshot field, `pending_replay_state` PerContextState field,
  `replay_state_snapshot()` / `restore_replay_state()` / `restore_epoch_high_water` calls.
- WASM_EXPORT_VERSION reverted 6->5. Version gate is EXACT-MATCH (rejects >5 AND <5,
  manager.rs ~6741/6760) before any snapshot field consumed → a captured v6 vulnerable
  envelope is rejected at the gate, not just field-dropped. Hard close.
- Fresh WASM crypto state (new_for_context + join_context_encrypted, manager.rs:2466)
  starts empty recv_sequence_tracker, empty SenderKeyStore, sender_key_epoch=1. No seed path.
- grep of crates/scp-ffi/wasm/src for restore_replay_state/pending_replay/replay_state/
  WasmReplayStateSnapshot = ZERO hits. Field is gone from the struct entirely (no home for
  cross-party replay state to live).
- In-session protections intact (decrypt_message state.rs:188): ceiling enforced BEFORE
  tracker (epoch > high_water + MAX_EPOCH_ADVANCE rejected), replay/reorder check, key
  lookup before tracker advance, tracker recorded ONLY on successful decrypt.
- Header framing unchanged (shared scp-protocol encrypt.rs:166): <16B → CiphertextTooShort,
  epoch 8B BE || seq 8B BE, no overflow. AAD = raw context_id. epoch = sender_key_epoch
  (not MLS epoch) — conformance test now drives REAL native seal/open across
  sender_key_epoch=2 vs MLS-epoch=1 divergence.
- 58/58 wasm_conformance tests pass. Clippy clean on wasm32 non-test build.

### Native two-snapshot architecture (the correct model WASM now matches)
- LOCAL same-node `MlsCryptoSnapshot` (provider.rs:105) DOES persist recv_sequence_tracker
  (line 159) — legit restart persistence, safe (own node, own authority).
- PORTABLE cross-party export (export_import.rs:819-820, 1015-1016) DELIBERATELY DROPS the
  freshness/replay cache: "no authority on a foreign node, fresh node opens its own window."
- WASM is ephemeral (ADR-034): its ONLY snapshot is the portable export → correctly
  persists tracker NOWHERE.

### BLACK-1909-S1 (LOW/provenance, NOT a code bug): spec still mandates the bug
- .docs/specs/09-security-model.md:1260 §9.16.1 STILL says verbatim:
  "The tracker is persisted in the crypto state snapshot."
- This sentence, read as applying to the portable export, IS BLACK-1909-01. A prior
  implementer read it literally → the vulnerability. Code now correct but diverges from
  the literal spec → phantom provenance (CLAUDE.md artifact-flow: fix spec FIRST).
- Spec conflates LOCAL snapshot (persist=correct) vs PORTABLE export (persist=vuln).
  Fix: line 1260 must distinguish — tracker persists in the LOCAL same-node crypto-state
  snapshot only; the portable cross-party export MUST NOT carry it (importer opens its own
  in-session receive window). Mirror the export_import.rs:819 rationale into the spec.
