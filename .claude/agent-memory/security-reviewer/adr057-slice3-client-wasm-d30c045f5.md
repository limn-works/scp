---
name: adr057-slice3-client-wasm-d30c045f5
description: Security audit of ADR-057 Slice 3 (scp-client-wasm wasm-bindgen browser surface), branch feat/adr057-3-client-wasm @ d30c045f5 — PASS, no blockers
metadata:
  type: project
---

# ADR-057 Slice 3 — scp-client-wasm (d30c045f5) — 2026-06-30 — PASS, ship as interim

New browser-facing security boundary: `wasm-bindgen` surface over `scp-client` (Slice 2 driver). 5 files: custody.rs / storage.rs / time.rs / error.rs / lib.rs + native host test. Build gates: native clippy clean, wasm32 build clean (forced rebuild), native test green (4 unit + 1 two-party surface exchange). No wasm-bindgen-test-runner in env (build-pipeline gap, documented).

## Verified sound
1. **unsafe impl Send+Sync** (custody.rs:144/146 JsSigner, storage.rs:95/97 JsStorageAdapter): wasm32-ONLY (`#[cfg(target_arch="wasm32")]`), LOCALIZED (shared scp-client `Signer`/`Storage`/`Clock` traits still `: Send+Sync` at signer.rs:30 / storage.rs:26 / primitives time.rs:82; native runtime uses real Send+Sync types). WasmClock is ZST (no unsafe needed). No wasm atomics/shared-memory threading enabled (grepped .cargo/config, crate — none). Embedder obligation (keep one client pinned per agent if wasm threads wired) honestly documented. JsValue = JS-heap index, cannot postMessage cross-agent. SOUND under current build.
2. **MLS signing key in wasm linear memory** — REAL gap vs ADR component-3 "keys never in wasm", HONESTLY disclosed (custody.rs module docs + signer.rs:15 scope note). `Signer` trait has NO sign() (only did()+signing_key_id()); MLS ed25519 SignatureKeyPair generated/held in scp-mls (crypto_state per-context, client.rs:56). JsKeyCustody.sign/dhAgree = typed SEAM, no call site (`#[allow(dead_code)] custody` field). In tab threat model XSS/supply-chain reads wasm memory anyway → WebCrypto-custody is defense-in-depth, not load-bearing. Interim ship ACCEPTABLE (ADR Slice-4/later custody slice tracked).
3. **Hardened clock** (time.rs) — faithful restore of deleted bridge (1a3b41a5e^) inline_js `const _dateNow = Date.now.bind(Date)` top-level capture at ES-module instantiation (before app override). Correctly scoped: SCP-layer clock ONLY, NOT openmls Lifetime clock (Prereq-1, fluvio_wasm_timer live Date.now still unhardened — documented, deferred). now_ms_u64 clamps neg→0 = fail-closed (oldest ts expires). Native fallback cfg'd out of browser build.
4. **Panic hook + error redaction** — scp_init hook (lib.rs:70, wasm32-only) interpolates ONLY static `location` (Location file:line), never payload. ClientError Display (error.rs) forwards MlsError/SenderKeyError msgs which interpolate openmls/serde `e.to_string()` = wire-object descriptions, NOT plaintext/key bytes (verified scp-mls encrypt.rs EncryptionFailed/DecryptionFailed sites). [SCP-CAT-NNN] prefixes stable.
5. **No raw key leak / no eval** — only inline_js = Date.now capture (no eval/Function). Only raw-key surface = local_sender_key_bytes (documented §9.16 hand-off MISSING SEAM, HPKE-seal deferred). install_sender_key has 32-byte guard. NO MLS signing/init-key bytes exposed. sender_did in receive_message resolved from MLS credential (authenticated outer layer), NOT caller — install_sender_key(wrongDID) = self-DoS only, no impersonation.

## Non-blocking observations
- ADR Prereq-4 (`panic=unwind` for browser build so encrypt.rs catch_unwind DoS-guard isn't a no-op) NOT configured in this crate (no wasm-pack profile here). Legit-deferred to Slice-3/4 build pipeline (TS SDK browser backend), but crate doesn't yet document/enforce it locally.
- Storage::get swallows JS throw → None (documented fail-to-absent; acceptable, browser read shouldn't throw).
- wasm-bindgen-test-runner absent → error-path JsValue wrapping only covered by wasm_tests (can't run natively). Build-pipeline item.
