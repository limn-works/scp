# ADR-057 Slice 3 — scp-client-wasm review (2026-06-30, @9b3080469)

Branch `feat/adr057-3-client-wasm`. wasm-bindgen browser surface over scp-client (thin, 17 methods).

## Verdict: CLEAN — no real defects. All builds/tests/clippy green.

- native build EXIT 0; wasm32 build EXIT 0; workspace build EXIT 0
- clippy native `-D warnings` EXIT 0; clippy wasm32 `--all-targets -D warnings` EXIT 0 (compiles wasm_bindgen_test cases)
- nextest 5/5 PASS (incl. the 2-party surface exchange)
- fence holds: no scp-runtime/scp-identity/tokio in tree (both targets)

## Key verifications (why it's genuinely correct)
- **Arg marshalling faithful:** every wasm method delegates 1:1 to ScpClient. Uint8Array↔Vec<u8>, u64↔bigint, String↔DID all match the underlying sigs. AddMemberOutput/SendOutput fields copied exactly. `install_sender_key` try_into [u8;32] with correct len error. `local_sender_key_bytes` returns [u8;32].to_vec(). `event_log_leaf_hashes` flattens Vec<[u8;32]> (deterministic sequence order, NOT hashmap). `member_dids` = Vec<String> (insertion order, convergent by wire adoption). `sender_did.0` — DID(pub String), valid.
- **JsValue::from_str DOES abort natively (SIGABRT, non-unwinding)** — empirically confirmed by probe test. This validates the whole test-strategy justification: native happy-path test builds NO JsValue (map_err/to_js/serialize_event_log construct JsValue only on Err branch), so the test is valid and drives real #[wasm_bindgen] bodies via from_parts (exact wiring from_js uses). Error mapping correctly split: pure error_code native unit tests + #[wasm_bindgen_test] for JsValue wrapping.
- **Storage::get swallows JS throw → None: NOT a live bug.** `storage` field is held but has ZERO read/write call sites in Slice-2 driver (grep-confirmed). Latent forward-looking note only; dormant-but-wired per storage.rs docs.
- **unsafe impl Send+Sync:** wasm32-only, single-tab model, JsValue can't cross agent boundary. No !Send field touched cross-thread (no threads wired). Sound.
- **wasm32 divergence:** only cast is `ms as u64` (f64→u64, target-independent). `hashes.len()*32` capacity hint could overflow at ~134M leaves on 32-bit usize (unreachable; capacity hint only, extend_from_slice grows correctly regardless). No iteration-order divergence.

## Minor observations (NOT defects, forward-looking)
- Storage::get error-swallow-to-None will matter once a snapshot read path is wired (a present-but-unreadable value read as absent could trigger overwrite). No call site today.
- custody.rs sign/dhAgree/generateKeypair externs are declared seams with no call site (honestly documented; MLS key lives in scp-mls per ADR-057 friction note). Not dead-code-gamed.
