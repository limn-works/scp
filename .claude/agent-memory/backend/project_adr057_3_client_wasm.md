---
name: project-adr057-3-client-wasm
description: ADR-057 Slice 3 — scp-client-wasm wasm-bindgen browser surface over scp-client; restored deleted-bridge infra; Send/Sync + JsValue-on-native frictions
metadata:
  type: project
---

ADR-057 Slice 3 (MVP): new crate `crates/scp-client-wasm` — a THIN `#[wasm_bindgen]` surface over `scp-client` (Slice 2's single-threaded participant driver). Branch `feat/adr057-3-client-wasm` @ d30c045f5, stacked on `feat/adr057-2-scp-client` (b4c1db87e). NOT pushed.

**Why:** ADR-057 Slice 3 = browser platform infra + wasm-bindgen surface, keys on-device. Restores deleted WASM bridge infra (`1a3b41a5e^`) adapted to drive scp-client's TRAITS, not the deleted protocol bodies.

**How to apply / key facts for a future slice or reviewer:**

- **Crate shape:** `crate-type=["cdylib","rlib"]` (rlib lets a NATIVE host test link the surface). wasm-bindgen stack split: `wasm-bindgen` is a BOTH-targets dep (inert `JsValue`/macro on native); `js-sys`/`web-sys`/`serde-wasm-bindgen`/getrandom-wasm are `cfg(target_arch="wasm32")`-only. Added to root `[workspace.dependencies]` + members. openmls arrives transitively via scp-client (no re-declare).

- **`scp-client` trait slots the surface fills:** `Clock` == `scp_primitives::Clock` (clean — `WasmClock` plugs straight in). `Storage` = sync get/put/delete (Result<_,String>). `Signer` = did()+signing_key_id() ONLY.

- **FRICTION 1 (reported, expected):** `scp_client::Signer` does NOT sign. The MLS ed25519 SignatureKeyPair is generated/held INSIDE scp-mls (create_group/generate_key_package) in wasm linear memory. So "private key never enters wasm" is NOT achievable through Signer in Slice 2/3 — acknowledged by scp-client signer.rs docstring; deferred to a future custody slice. Restored full `JsKeyCustody` extern (sign/getPublicKey/generateKeypair/destroyKey/dhAgree) as the SEAM (no call site yet) so the custody slice routes the MLS key through it without a signature change. No scp-client trait change made.

- **FRICTION 2 (Send/Sync):** scp-client traits require `Send+Sync`; JS externs (`JsStorage`/`JsKeyCustody`) are `!Send+!Sync`. Resolved with a LOCALIZED `unsafe impl Send/Sync` on the adapter newtypes, gated to wasm32, justified by single-tab driver model. Did NOT relax the shared trait bounds. Documented embedder obligation: JsValue is a heap index that can't cross a wasm worker-agent boundary, so one client must stay pinned to one agent if shared-memory threads are ever wired.

- **GOTCHA — JsValue aborts on native:** `JsValue::from_str`/`as_string` PANIC (SIGABRT, "cannot call wasm-bindgen imported functions on non-wasm targets") on the native host. Consequences: (a) error-mapping unit tests must test a PURE `error_code(&ClientError)->&str` fn, NOT `to_js`; JsValue-content asserts go in a `cfg(all(test,target_arch="wasm32"))` `#[wasm_bindgen_test]` block. (b) A native-surface integration test CANNOT exercise any error-return path — building the `Err(JsValue)` aborts before returning. Only happy paths run natively. Error mapping is covered by the pure-fn unit test + wasm-target test instead.

- **Toolchain reality (this env):** wasm32 target + `wasm-pack 0.14.0` + node 25 + bun 1.3.9 PRESENT; `wasm-bindgen-test-runner` ABSENT. So the strongest proof was `wasm-pack build --target nodejs` + a node driver script (`/tmp/scp-client-wasm-pkg/drive.mjs`) driving the real wasm 2-party exchange with JS-injected custody/storage — PASSES. Plus a native-surface Rust test (happy-path). Both green. The missing wasm-test-runner is a real build-pipeline gap to report.

- **Gates all green:** wasm32 build exit 0; fence cargo-tree (native+wasm32) = 0 hits for scp-runtime/scp-identity/tokio; full CI workspace clippy `-D warnings` clean; fmt clean; native test 4 unit + 1 integration pass. Clippy nits hit: doc_markdown backticks (WebCrypto/KeyPackage/MessagePack), use_self in `#[wasm_bindgen(constructor)]` return (Self WORKS there), too_many_lines on the test (deny=100 — factor helpers, don't allow).

- Event-log stream crosses the boundary as `rmp_serde` MessagePack (name-tagged, width/endianness-independent per ADR-057); joiner deserializes + replays. `drainEvents` returns `WasmReceivedEvent{kind,senderDid,payload}` (only MessageReceived buffered today; forward-safe kind string for others).
