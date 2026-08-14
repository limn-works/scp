---
name: wasm-1909-phase2-sender-layer-6952efad
description: #1909 Phase 2 WASM↔native sender-layer interop review @ 6952efad — ALIGNED, 1 finding (issue-refs in source)
metadata:
  type: project
---

# #1909 Phase 2 WASM Sender-Layer Convergence @ `6952efad` (2026-06-28) — ALIGNED

Commit `6952efad7` (HEAD of worktree 1909-p2-wasm; Phase 1 base = `598a56c37` raw-context_id AAD). 9 files +935/-201. Completes WASM↔native sender-layer ciphertext interop per spec §9.16 (.docs/specs/09-security-model.md).

**Why:** #1877 / #1909 two-phase plan. Phase 1 (raw context_id in AAD) merged as PR #1921. Phase 2 = epoch semantics + replay tracker + 16-byte header framing.

**How to apply:** Verdict ALIGNED. WASM↔native sender layer NOW interoperates by construction. ONE finding: 3 issue-refs in source (violates no-issue-refs-in-code). NOT a blocker but should be fixed before merge.

## Verified spec-faithful
- **Header framing §9.16.1**: WASM `encrypt_message` (state.rs:166) calls SHARED `scp_protocol::crypto::sender_keys::encrypt::build_sender_header`; native `seal` calls same. 16-byte `epoch(8B BE)||seq(8B BE)`. Byte-identical by construction (shared code, not reimpl).
- **Decrypt ordering §9.16.1** (state.rs:213): MLS decrypt → parse_sender_header (authoritative) → epoch-ceiling BEFORE replay tracker (line 225-232) → replay reject `epoch<last_epoch || (epoch==last_epoch && seq<=last_seq)` (line 243, EXACT MUST) → key lookup before tracker advance → record tracker ONLY after successful sender-key decrypt (line 274). Defense-in-depth beyond spec.
- **§9.16.5 epoch**: WASM INITIAL_SENDER_KEY_EPOCH=1 matches native provider.rs:765 `sender_key_epoch:1` (NOT spec's literal "starting at 0" — known native convention, pre-existing, consistent). Advanced only on rotation.
- **§9.16.1 MUST-persist tracker**: WASM rides replay_state in the SIGNED context-export snapshot (`WasmContextExportSnapshot.replay_state`, manager.rs:6656) — fed into BOTH HMAC and Ed25519 digest (JCS preimage). Import parks into `pending_replay_state` (manager.rs:7218); on encrypted join (line 2495) `restore_replay_state` seeds the freshly-Welcome-established WasmCryptoState. This is the SPEC-FAITHFUL ADR-034 adaptation (WASM import = crypto:None; crypto from Welcome), NOT a deviation. Native has its OWN MlsCryptoSnapshot.recv_sequence_tracker (provider.rs) — native §23.16.4 context-export needs NO parallel change.
- **MAX_EPOCH_ADVANCE=1000** promoted to shared `scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE`; native provider + lifecycle_helpers now import it (was `pub(crate)` dup). Traces to spec §9.16.1:1262 "epoch > current_epoch + 1000".
- **API change**: `context_decrypt_message` dropped epoch/sequence JS args. TS SDK does NOT break — `bindings/typescript/src/` never calls the WASM fn; TS SCP class is NAPI-only (throws on `new SCP()` in browser/WASM per sdk-capability-matrix.json:254). WASM `context_decrypt_message` is a direct browser-JS entry (reconnect driver feeds relay blobs). All internal callers at the commit use new 3-arg arity.
- **Export version 5→6**: `WASM_EXPORT_VERSION:u32=6` + strict equality import (`version != 6` rejects both newer AND older). Pre-release, no migration — dropping v5 compat is correct. WASM-local (native unaffected).
- No enforcement files touched. No phantom provenance.

## FINDING (informational, fix preferred): issue-refs in source
Violates `feedback_no_issue_refs_in_code` (#NNNN only in PR/commit, never source):
- state.rs:10 `//! ... cross-decrypt (§9.16.1 / #1877)`
- state.rs:60 `/// rejecting epoch regressions after restore (#1608 parity).`
- wasm_conformance.rs:2002 `/// Cross-family ... (§9.16.1 / #1877, #1909 Phase 2).`
All already carry §9.16.1 cites — drop the #refs (or keep §-cite only).

## OBSERVATION (test precision, not a defect)
`cross_family_sender_layer_header_and_aad_converge` (wasm_conformance.rs:2019) is somewhat tautological: both "native framing" and "WASM framing" call the SAME shared `build_sender_header`/`encrypt_sender_layer`/`decrypt_sender_layer` — it tests the shared lib against itself, not the two bridge wrappers (native `seal` vs WASM `encrypt_message`) against each other. Convergence still holds because both bridges genuinely delegate to those primitives (verified). Framing as "native vs WASM" overstates direct coverage.

## GOTCHA
Worktree had UNCOMMITTED reverts (version back to 5, decrypt back to 5-arg). MUST read `git show 6952efad:<file>` — working-tree greps gave false OLD-signature hits. Confirms orchestrator-verify lesson.

## #1909 closure
Phase 1 (merged) + Phase 2 (this) = TRUE sender-layer interop. PR should `Closes #1909` in BODY. No remaining sender-layer gaps observed.
